//! Map generic segment-resolver failures through SS's architectural fault lane.

use crate::{CpuError, SegmentFaultReason, registers::SegmentRegister};

use super::{AccessKind, LogicalSpan};

pub(super) fn limit_fault(
    span: LogicalSpan,
    offset: u32,
    kind: AccessKind,
    ip: u32,
) -> CpuError {
    if span.register == SegmentRegister::Ss {
        // Current-stack limit and wrap failures encode a null selector index.
        CpuError::StackSegmentFault {
            error_code: 0,
            ip,
        }
    } else {
        CpuError::SegmentFault {
            selector: span.selector,
            offset,
            access: kind.segment_access(),
            reason: SegmentFaultReason::Limit,
        }
    }
}

pub(super) fn map_stack_error(
    error: CpuError,
    register: SegmentRegister,
    ip: u32,
) -> CpuError {
    if register != SegmentRegister::Ss {
        return error;
    }
    match error {
        CpuError::SegmentFault {
            reason: SegmentFaultReason::Limit,
            ..
        } => CpuError::StackSegmentFault { error_code: 0, ip },
        CpuError::SegmentFault {
            selector,
            reason: SegmentFaultReason::NotPresent,
            ..
        } => CpuError::StackSegmentFault {
            error_code: u32::from(selector & 0xfffc),
            ip,
        },
        CpuError::SegmentNotPresentFault { error_code, .. } => {
            CpuError::StackSegmentFault { error_code, ip }
        }
        other => other,
    }
}

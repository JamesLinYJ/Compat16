//! Value transfers over complete, preflighted CPU memory spans.

use crate::{
    CpuError,
    memory_access::{AccessKind, AccessRequest, CpuBus, DataAlignment, LogicalSpan, PreparedAccess},
};

pub(crate) fn read_bytes(
    bus: &mut impl CpuBus,
    span: LogicalSpan,
    kind: AccessKind,
    alignment: DataAlignment,
    bytes: &mut [u8],
) -> Result<(), CpuError> {
    check_length(bus, span.len, bytes.len())?;
    let access = bus.prepare(AccessRequest::instruction(span, kind, alignment))?;
    bus.read_prepared(&access, bytes)
}

pub(crate) fn write_bytes(
    bus: &mut impl CpuBus,
    span: LogicalSpan,
    kind: AccessKind,
    alignment: DataAlignment,
    bytes: &[u8],
) -> Result<(), CpuError> {
    check_length(bus, span.len, bytes.len())?;
    let access = bus.prepare(AccessRequest::instruction(span, kind, alignment))?;
    bus.write_prepared(access, bytes)
}

pub(crate) fn read_width(
    bus: &mut impl CpuBus,
    span: LogicalSpan,
    kind: AccessKind,
) -> Result<u32, CpuError> {
    let width = checked_width(bus, span.len)?;
    let access = bus.prepare(AccessRequest::instruction(
        span,
        kind,
        DataAlignment::Natural(width),
    ))?;
    read_prepared_width(bus, &access, width)
}

pub(crate) fn write_width(
    bus: &mut impl CpuBus,
    span: LogicalSpan,
    kind: AccessKind,
    value: u32,
) -> Result<(), CpuError> {
    let width = checked_width(bus, span.len)?;
    let access = bus.prepare(AccessRequest::instruction(
        span,
        kind,
        DataAlignment::Natural(width),
    ))?;
    write_prepared_width(bus, access, width, value)
}

pub(crate) fn read_prepared_width(
    bus: &mut impl CpuBus,
    access: &PreparedAccess,
    width: u8,
) -> Result<u32, CpuError> {
    let width = usize::from(checked_width(bus, usize::from(width))?);
    // Instruction operands select 1, 2 or 4 bytes at runtime. A fixed wire
    // struct cannot express that union; the checked bus owns address mapping,
    // and Rust's little-endian conversion owns only the scalar representation.
    let mut bytes = [0; 4];
    bus.read_prepared(access, &mut bytes[..width])?;
    Ok(u32::from_le_bytes(bytes))
}

pub(crate) fn write_prepared_width(
    bus: &mut impl CpuBus,
    access: PreparedAccess,
    width: u8,
    value: u32,
) -> Result<(), CpuError> {
    let width = usize::from(checked_width(bus, usize::from(width))?);
    bus.write_prepared(access, &value.to_le_bytes()[..width])
}

fn checked_width(bus: &impl CpuBus, width: usize) -> Result<u8, CpuError> {
    if matches!(width, 1 | 2 | 4) {
        Ok(width as u8)
    } else {
        Err(invalid_plan(bus))
    }
}

fn check_length(bus: &impl CpuBus, expected: usize, actual: usize) -> Result<(), CpuError> {
    if expected == actual { Ok(()) } else { Err(invalid_plan(bus)) }
}

fn invalid_plan(bus: &impl CpuBus) -> CpuError {
    CpuError::InvalidMemoryAccessPlan { ip: bus.instruction_site().ip }
}

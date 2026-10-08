//! Checked decoder for OLE2DISP, OLE2NLS, and TYPELIB stack calls.

use guest_core::GuestMemory;

use crate::{SelectorTable, Win16Argument, Win16Error};
use super::Win16ExportDescriptor;
use super::super::Win16ParameterType;
use super::request::{
    Win16AutomationArgument as Arg, Win16AutomationCall, Win16AutomationFamily as Family,
};

const MAX_AUTOMATION_COPY: usize = 1 << 20;

pub(super) fn decode(
    descriptor: &Win16ExportDescriptor,
    arguments: &[Win16Argument],
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Win16AutomationCall, Win16Error> {
    let family = match descriptor.id.module() {
        module if module.eq_ignore_ascii_case("OLE2DISP") => Family::Ole2Disp,
        module if module.eq_ignore_ascii_case("OLE2NLS") => Family::Ole2Nls,
        module if module.eq_ignore_ascii_case("TYPELIB") => Family::TypeLib,
        _ => return Err(Win16Error::InvalidRange),
    };
    if arguments.len() != descriptor.parameters.len() {
        return Err(Win16Error::InvalidRange);
    }

    let ordinal = descriptor.ordinal();
    let mut decoded = Vec::with_capacity(arguments.len());
    for (index, (parameter, argument)) in descriptor.parameters.iter()
        .zip(arguments).enumerate()
    {
        if family == Family::Ole2Nls && is_counted_nls_source(ordinal, index) {
            let far = dword(argument)?;
            let count_index = nls_source_count_index(ordinal, index)
                .ok_or(Win16Error::InvalidRange)?;
            let count = descriptor.parameters.get(count_index)
                .and_then(|_| arguments.get(count_index)).ok_or(Win16Error::InvalidRange)?;
            let count = word(count)? as i16;
            decoded.push(Arg::CountedAnsiString {
                bytes: read_counted_ansi(far, count, selectors, memory)?,
                declared_count: count,
                is_null: far == 0,
            });
            continue;
        }

        if family == Family::Ole2Disp && matches!(ordinal, 4 | 5) {
            let input_index = if ordinal == 4 { 0 } else { 1 };
            if index == input_index {
                let far = dword(argument)?;
                let count = word(arguments.get(input_index + 1).ok_or(Win16Error::InvalidRange)?)?;
                let bytes = if far == 0 {
                    None
                } else {
                    Some(read_guest_bytes(
                        far, usize::from(count), selectors, memory,
                    )?)
                };
                decoded.push(Arg::CountedBstrBytes(bytes));
                continue;
            }
        }

        if family == Family::Ole2Disp && ordinal == 15 && index == 2 {
            let far = dword(argument)?;
            let dimensions = usize::from(word(arguments.get(1).ok_or(Win16Error::InvalidRange)?)?);
            let byte_count = dimensions.checked_mul(8).ok_or(Win16Error::InvalidRange)?;
            if byte_count > MAX_AUTOMATION_COPY {
                return Err(Win16Error::InvalidRange);
            }
            decoded.push(Arg::ExactBytes(if far == 0 {
                None
            } else {
                Some(read_guest_bytes(far, byte_count, selectors, memory)?)
            }));
            continue;
        }

        let raw = raw(argument)?;
        decoded.push(match parameter.parameter_type {
            Win16ParameterType::FarString => {
                if family == Family::Ole2Disp && matches!(ordinal, 2 | 3) && raw == 0 {
                    Arg::NullableAnsiString(None)
                } else {
                    Arg::AnsiString(crate::strings::read_ansi_z(
                        selectors, memory, raw, crate::MAX_WIN16_STRING_BYTES,
                    )?)
                }
            }
            Win16ParameterType::NullableFarString => Arg::NullableAnsiString(
                if raw == 0 { None } else {
                    Some(crate::strings::read_ansi_z(
                        selectors, memory, raw, crate::MAX_WIN16_STRING_BYTES,
                    )?)
                },
            ),
            Win16ParameterType::FarPointer
            | Win16ParameterType::FarBuffer
            | Win16ParameterType::FarOutputBuffer
            | Win16ParameterType::FarStringOrChar
            | Win16ParameterType::ResourceName
            | Win16ParameterType::AtomName
            | Win16ParameterType::ClassName => Arg::GuestAddress(raw),
            Win16ParameterType::Scalar | Win16ParameterType::SignedScalar => {
                match argument {
                    Win16Argument::Word(value) => Arg::Word(*value),
                    Win16Argument::Dword(value) => Arg::Dword(*value),
                    Win16Argument::Byte(value) => Arg::Word(u16::from(*value)),
                }
            }
        });
    }

    Ok(Win16AutomationCall { family, ordinal, arguments: decoded })
}

fn is_counted_nls_source(ordinal: u16, index: usize) -> bool {
    matches!((ordinal, index), (6 | 7, 2) | (8, 2 | 4))
}

fn nls_source_count_index(ordinal: u16, source_index: usize) -> Option<usize> {
    match (ordinal, source_index) {
        (6 | 7, 2) => Some(3),
        (8, 2) => Some(3),
        (8, 4) => Some(5),
        _ => None,
    }
}

fn raw(argument: &Win16Argument) -> Result<u32, Win16Error> {
    match argument {
        Win16Argument::Word(value) => Ok(u32::from(*value)),
        Win16Argument::Dword(value) => Ok(*value),
        Win16Argument::Byte(value) => Ok(u32::from(*value)),
    }
}

fn dword(argument: &Win16Argument) -> Result<u32, Win16Error> {
    match argument {
        Win16Argument::Dword(value) => Ok(*value),
        _ => Err(Win16Error::InvalidRange),
    }
}

fn word(argument: &Win16Argument) -> Result<u16, Win16Error> {
    match argument {
        Win16Argument::Word(value) => Ok(*value),
        _ => Err(Win16Error::InvalidRange),
    }
}

fn read_counted_ansi(
    far: u32,
    count: i16,
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Vec<u8>, Win16Error> {
    if far == 0 { return Ok(Vec::new()); }
    match count {
        -1 => crate::strings::read_ansi_z(selectors, memory, far, crate::MAX_WIN16_STRING_BYTES),
        value if value >= 0 => read_guest_bytes(far, value as usize, selectors, memory),
        _ => Ok(Vec::new()),
    }
}

/// Copy an explicit guest byte extent while respecting selector limits. A
/// segment transition is permitted only through the selector table's checked
/// continuation for the same allocation.
fn read_guest_bytes(
    far: u32,
    mut remaining: usize,
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Vec<u8>, Win16Error> {
    if remaining == 0 { return Ok(Vec::new()); }
    if remaining > MAX_AUTOMATION_COPY { return Err(Win16Error::InvalidRange); }
    let mut output = Vec::new();
    output.try_reserve_exact(remaining).map_err(|_| Win16Error::InvalidRange)?;
    output.resize(remaining, 0);
    let mut pointer = selectors.pointer_from_far(far)?;
    let mut offset = 0;
    while remaining > 0 {
        let descriptor = selectors.describe(pointer.selector())?;
        let available = descriptor.limit.checked_sub(u32::from(pointer.offset()))
            .and_then(|count| count.checked_add(1))
            .and_then(|count| usize::try_from(count).ok())
            .ok_or(Win16Error::InvalidRange)?;
        let count = remaining.min(available);
        if count == 0 { return Err(Win16Error::InvalidRange); }
        let end = offset.checked_add(count).ok_or(Win16Error::InvalidRange)?;
        selectors.read(memory, pointer, &mut output[offset..end])?;
        remaining -= count;
        offset = end;
        if remaining > 0 {
            pointer = selectors.add_bytes(
                pointer,
                u32::try_from(count).map_err(|_| Win16Error::InvalidRange)?,
            )?;
        }
    }
    Ok(output)
}

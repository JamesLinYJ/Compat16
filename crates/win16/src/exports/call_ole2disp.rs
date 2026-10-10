//! Checked decoder for the guest-local OLE2DISP BSTR/VARIANT/SAFEARRAY calls.

use guest_core::GuestMemory;

use super::request::{Win16Ole2DispArgument as Arg, Win16Ole2DispCall};
use super::{
    Win16ExportDescriptor,
    call::call_helpers::{dword_argument, word_argument},
};
use crate::{Access, SelectorTable, Win16Argument, Win16Error, Win16ParameterType};

const MAX_OLE2DISP_COPY: usize = 1 << 20;

const fn supported_guest_ordinal(ordinal: u16) -> bool {
    matches!(ordinal, 2..=11 | 15..=25 | 27 | 38..=41 | 109)
}

pub(super) fn decode(
    descriptor: &Win16ExportDescriptor,
    arguments: &[Win16Argument],
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Win16Ole2DispCall, Win16Error> {
    if !descriptor.id.module().eq_ignore_ascii_case("OLE2DISP")
        || !supported_guest_ordinal(descriptor.ordinal())
        || arguments.len() != descriptor.parameters.len()
    {
        return Err(Win16Error::InvalidRange);
    }

    let ordinal = descriptor.ordinal();
    let mut decoded = Vec::with_capacity(arguments.len());
    for (index, (parameter, argument)) in descriptor.parameters.iter().zip(arguments).enumerate() {
        if matches!(ordinal, 4 | 5) {
            let input_index = if ordinal == 4 { 0 } else { 1 };
            if index == input_index {
                let far = dword_argument(arguments, input_index)?;
                let count = usize::from(word_argument(arguments, input_index + 1)?);
                let bytes = if far == 0 {
                    None
                } else {
                    Some(read_guest_far_bytes(far, count, selectors, memory)?)
                };
                decoded.push(Arg::CountedBstrBytes(bytes));
                continue;
            }
        }

        if ordinal == 15 && index == 2 {
            let far = dword_argument(arguments, index)?;
            let dimensions = usize::from(word_argument(arguments, 1)?);
            let byte_count = dimensions.checked_mul(8).ok_or(Win16Error::InvalidRange)?;
            if byte_count > MAX_OLE2DISP_COPY {
                return Err(Win16Error::InvalidRange);
            }
            decoded.push(Arg::ExactBytes(if far == 0 {
                None
            } else {
                Some(read_guest_far_bytes(far, byte_count, selectors, memory)?)
            }));
            continue;
        }

        let raw = raw(argument)?;
        decoded.push(match parameter.parameter_type {
            Win16ParameterType::FarString => {
                if matches!(ordinal, 2 | 3) && raw == 0 {
                    Arg::NullableAnsiString(None)
                } else {
                    Arg::AnsiString(read_single_far_string(raw, selectors, memory)?)
                }
            }
            Win16ParameterType::NullableFarString => Arg::NullableAnsiString(if raw == 0 {
                None
            } else {
                Some(read_single_far_string(raw, selectors, memory)?)
            }),
            Win16ParameterType::FarPointer
            | Win16ParameterType::FarBuffer
            | Win16ParameterType::FarOutputBuffer
            | Win16ParameterType::FarStringOrChar
            | Win16ParameterType::ResourceName
            | Win16ParameterType::AtomName
            | Win16ParameterType::ClassName => Arg::GuestAddress(raw),
            Win16ParameterType::Scalar | Win16ParameterType::SignedScalar => match argument {
                Win16Argument::Word(value) => Arg::Word(*value),
                Win16Argument::Dword(value) => Arg::Dword(*value),
                Win16Argument::Byte(value) => Arg::Word(u16::from(*value)),
            },
        });
    }

    Ok(Win16Ole2DispCall {
        ordinal,
        arguments: decoded,
    })
}

fn raw(argument: &Win16Argument) -> Result<u32, Win16Error> {
    match argument {
        Win16Argument::Word(value) => Ok(u32::from(*value)),
        Win16Argument::Dword(value) => Ok(*value),
        Win16Argument::Byte(value) => Ok(u32::from(*value)),
    }
}

fn read_guest_far_bytes(
    far: u32,
    length: usize,
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Vec<u8>, Win16Error> {
    if length > MAX_OLE2DISP_COPY {
        return Err(Win16Error::InvalidRange);
    }
    let pointer = selectors.pointer_from_far(far)?;
    selectors.translate(pointer, Access::Read, length, memory)?;
    let mut output = Vec::new();
    output
        .try_reserve_exact(length)
        .map_err(|_| Win16Error::OutOfMemory)?;
    output.resize(length, 0);
    selectors.read(memory, pointer, &mut output)?;
    Ok(output)
}

fn read_single_far_string(
    far: u32,
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Vec<u8>, Win16Error> {
    let start = selectors.pointer_from_far(far)?;
    let descriptor = selectors.describe(start.selector())?;
    if !descriptor.present {
        return Err(Win16Error::InvalidSelector);
    }
    if !descriptor.rights.readable() {
        return Err(Win16Error::AccessDenied {
            access: Access::Read,
        });
    }
    let segment_remaining = 0x1_0000_usize - usize::from(start.offset());
    let descriptor_remaining = descriptor
        .limit
        .checked_sub(u32::from(start.offset()))
        .and_then(|count| count.checked_add(1))
        .and_then(|count| usize::try_from(count).ok())
        .ok_or(Win16Error::InvalidRange)?;
    let count = segment_remaining
        .min(descriptor_remaining)
        .min(crate::MAX_WIN16_STRING_BYTES);
    let mut output = Vec::new();
    output
        .try_reserve_exact(count.min(128))
        .map_err(|_| Win16Error::OutOfMemory)?;
    for offset in 0..count {
        let pointer = selectors.add_bytes(
            start,
            u32::try_from(offset).map_err(|_| Win16Error::InvalidRange)?,
        )?;
        let mut byte = [0];
        selectors.read(memory, pointer, &mut byte)?;
        if byte[0] == 0 {
            return Ok(output);
        }
        output.try_reserve(1).map_err(|_| Win16Error::OutOfMemory)?;
        output.push(byte[0]);
    }
    Err(Win16Error::InvalidRange)
}

//! Checked decoder for the signed scalar, string, BSTR, and VARIANT conversions.

use guest_core::GuestMemory;

use super::Win16ExportDescriptor;
use super::request::{
    Win16Ole2DispConvertCall as Call, Win16Ole2DispConvertInput as Input,
    Win16Ole2DispConvertOperation as Operation, Win16Ole2DispLocaleFlags,
};
use crate::{SelectorTable, Win16Argument, Win16Error};

const MAX_OLE2DISP_STRING: usize = 64 * 1024;

const fn supported(ordinal: u16) -> bool {
    matches!(
        ordinal,
        12 | 43..=48 | 50 | 56 | 61 | 64 | 72 | 80 | 88 | 91..=98 | 108 | 116..=125 | 131
    )
}

pub(super) fn decode(
    descriptor: &Win16ExportDescriptor,
    arguments: &[Win16Argument],
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Call, Win16Error> {
    let ordinal = descriptor.ordinal();
    if !descriptor.id.module().eq_ignore_ascii_case("OLE2DISP")
        || !supported(ordinal)
        || arguments.len() != descriptor.parameters.len()
    {
        return Err(Win16Error::InvalidRange);
    }

    let operation = match ordinal {
        12 => Operation::VariantChangeType {
            destination_far: dword(arguments, 0)?,
            source_far: dword(arguments, 1)?,
            flags: word(arguments, 2)?,
            target_vartype: word(arguments, 3)?,
            lcid: None,
        },
        108 => Operation::VariantChangeType {
            destination_far: dword(arguments, 0)?,
            source_far: dword(arguments, 1)?,
            lcid: Some(dword(arguments, 2)?),
            flags: word(arguments, 3)?,
            target_vartype: word(arguments, 4)?,
        },
        _ => decode_var_from(ordinal, arguments, selectors, memory)?,
    };
    Ok(Call { operation })
}

fn decode_var_from(
    ordinal: u16,
    arguments: &[Win16Argument],
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Operation, Win16Error> {
    let (input, locale_index, output_index) = match ordinal {
        43 => (
            Input::I4(i32::from_le_bytes(dword(arguments, 0)?.to_le_bytes())),
            None,
            1,
        ),
        44 => (Input::R4Bits(dword(arguments, 0)?), None, 1),
        45..=47 => (wide_input(ordinal, arguments)?, None, 2),
        48 | 56 | 64 | 72 | 80 | 88 | 122 => (
            read_string_input(dword(arguments, 0)?, selectors, memory)?,
            Some(1),
            3,
        ),
        50 | 124 => (Input::Bool(word(arguments, 0)? as i16), None, 1),
        61 => (wide_input(ordinal, arguments)?, None, 2),
        91 => (Input::I2(word(arguments, 0)? as i16), Some(1), 3),
        92 => (
            Input::I4(i32::from_le_bytes(dword(arguments, 0)?.to_le_bytes())),
            Some(1),
            3,
        ),
        93 => (Input::R4Bits(dword(arguments, 0)?), Some(1), 3),
        94..=96 => (wide_input(ordinal, arguments)?, Some(2), 4),
        97 => (Input::InterfaceFar(dword(arguments, 0)?), Some(1), 3),
        98 => (Input::Bool(word(arguments, 0)? as i16), Some(1), 3),
        116 => (Input::I2(word(arguments, 0)? as i16), None, 1),
        117 => (
            Input::I4(i32::from_le_bytes(dword(arguments, 0)?.to_le_bytes())),
            None,
            1,
        ),
        118 => (Input::R4Bits(dword(arguments, 0)?), None, 1),
        119..=121 => (wide_input(ordinal, arguments)?, None, 2),
        123 => (Input::InterfaceFar(dword(arguments, 0)?), Some(1), 2),
        125 => (Input::Ui1(word(arguments, 0)? as u8), None, 1),
        131 => (Input::Ui1(word(arguments, 0)? as u8), Some(1), 3),
        _ => return Err(Win16Error::InvalidRange),
    };

    let locale = match locale_index {
        Some(index) => Some(Win16Ole2DispLocaleFlags {
            lcid: dword(arguments, index)?,
            dw_flags: if matches!(ordinal, 123) {
                0
            } else {
                dword(arguments, index + 1)?
            },
        }),
        None => None,
    };
    Ok(Operation::VarFrom {
        ordinal,
        input,
        locale,
        output_far: dword(arguments, output_index)?,
    })
}

fn wide_input(ordinal: u16, arguments: &[Win16Argument]) -> Result<Input, Win16Error> {
    let first = dword(arguments, 0)?;
    let second = dword(arguments, 1)?;
    // The owned spec spells an eight-byte operand as two `long` slots. The
    // historical 16-bit wrappers receive `high` then `low` and compose
    // `high << 32 | low`; the SDK 3.1 collection has no OLE2DISP prototype.
    let bits = (u64::from(first) << 32) | u64::from(second);
    Ok(match ordinal {
        46 | 95 | 120 => Input::CurrencyBits(bits),
        47 | 96 | 121 => Input::DateBits(bits),
        _ => Input::R8Bits(bits),
    })
}

fn read_string_input(
    far: u32,
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Input, Win16Error> {
    if far == 0 {
        return Ok(Input::AnsiString(None));
    }
    let start = selectors.pointer_from_far(far)?;
    let descriptor = selectors.describe(start.selector())?;
    if !descriptor.present {
        return Err(Win16Error::InvalidSelector);
    }
    if !descriptor.rights.readable() {
        return Err(Win16Error::AccessDenied {
            access: crate::Access::Read,
        });
    }
    let selector_remaining = 0x1_0000_usize - usize::from(start.offset());
    let descriptor_remaining = descriptor
        .limit
        .checked_sub(u32::from(start.offset()))
        .and_then(|count| count.checked_add(1))
        .and_then(|count| usize::try_from(count).ok())
        .ok_or(Win16Error::InvalidRange)?;
    let limit = selector_remaining
        .min(descriptor_remaining)
        .min(MAX_OLE2DISP_STRING);
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(limit.min(128))
        .map_err(|_| Win16Error::OutOfMemory)?;
    for offset in 0..limit {
        let pointer = selectors.add_bytes(
            start,
            u32::try_from(offset).map_err(|_| Win16Error::InvalidRange)?,
        )?;
        let mut byte = [0];
        selectors.read(memory, pointer, &mut byte)?;
        if byte[0] == 0 {
            return Ok(Input::AnsiString(Some(bytes)));
        }
        bytes.try_reserve(1).map_err(|_| Win16Error::OutOfMemory)?;
        bytes.push(byte[0]);
    }
    Err(Win16Error::InvalidRange)
}

fn dword(arguments: &[Win16Argument], index: usize) -> Result<u32, Win16Error> {
    match arguments.get(index) {
        Some(Win16Argument::Dword(value)) => Ok(*value),
        _ => Err(Win16Error::InvalidRange),
    }
}

fn word(arguments: &[Win16Argument], index: usize) -> Result<u16, Win16Error> {
    match arguments.get(index) {
        Some(Win16Argument::Word(value)) => Ok(*value),
        Some(Win16Argument::Byte(value)) => Ok(u16::from(*value)),
        _ => Err(Win16Error::InvalidRange),
    }
}

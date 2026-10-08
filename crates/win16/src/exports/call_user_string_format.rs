//! USER.420/.421 guest-stack and FAR argument-list decoding.

use super::call_helpers::{checked_output_buffer, dword_argument};
use super::*;
use crate::string_format::{
    FormatArgumentKind, FormatPlan, RawFormatArgument, USER_FORMAT_OUTPUT_CAPACITY,
};
use crate::{ArgumentKind, Win16Argument, Win16CallingConvention};

const WSPRINTF_FIXED_ARGUMENTS: [ArgumentKind; 2] = [
    ArgumentKind::Dword,
    ArgumentKind::Dword,
];

/// Decode USER.420's CDECL call after its format string determines the
/// guest-side vararg slot widths. The caller still owns all argument cleanup.
pub(super) fn decode_wsprintf(
    descriptor: &Win16ExportDescriptor,
    frame: Win16CallFrame,
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<DecodedWin16Call, Win16Error> {
    if descriptor.id != Win16ExportId::UserWsprintf {
        return Err(Win16Error::InvalidRange);
    }
    let fixed = frame.decode_arguments(
        selectors,
        memory,
        Win16CallingConvention::Cdecl,
        &WSPRINTF_FIXED_ARGUMENTS,
    )?;
    let output_far = dword_argument(&fixed, 0)?;
    let format_far = dword_argument(&fixed, 1)?;
    let format = read_format(format_far, selectors, memory)?;
    let plan = FormatPlan::parse(&format)?;

    let mut signature = Vec::new();
    signature
        .try_reserve_exact(WSPRINTF_FIXED_ARGUMENTS.len() + plan.arguments().len())
        .map_err(|_| Win16Error::OutOfMemory)?;
    signature.extend_from_slice(&WSPRINTF_FIXED_ARGUMENTS);
    for argument in plan.arguments() {
        signature.push(match argument {
            FormatArgumentKind::Word => ArgumentKind::Word,
            FormatArgumentKind::Dword | FormatArgumentKind::FarString => ArgumentKind::Dword,
        });
    }
    let decoded_arguments = frame.decode_arguments(
        selectors,
        memory,
        Win16CallingConvention::Cdecl,
        &signature,
    )?;
    let values = raw_arguments(&decoded_arguments[2..], plan.arguments())?;
    let request = make_request(
        output_far,
        &format,
        &plan,
        &values,
        selectors,
        memory,
    )?;
    let stack_cleanup = frame.cleanup(Win16CallingConvention::Cdecl, &signature)?;
    Ok(DecodedWin16Call {
        export: descriptor.id,
        request: Win16ApiRequest::User(Win16UserRequest::StringFormat(request)),
        stack_cleanup,
    })
}

/// Decode USER.421's Pascal fixed arguments and its explicit FAR WORD list.
pub(super) fn decode_wvsprintf(
    arguments: &[Win16Argument],
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Win16ApiRequest, Win16Error> {
    let output_far = dword_argument(arguments, 0)?;
    let format_far = dword_argument(arguments, 1)?;
    let list_far = dword_argument(arguments, 2)?;
    let format = read_format(format_far, selectors, memory)?;
    let plan = FormatPlan::parse(&format)?;
    let values = read_argument_list(list_far, &plan, selectors, memory)?;
    let request = make_request(
        output_far,
        &format,
        &plan,
        &values,
        selectors,
        memory,
    )?;
    Ok(Win16ApiRequest::User(Win16UserRequest::StringFormat(request)))
}

fn read_format(
    far_pointer: u32,
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Vec<u8>, Win16Error> {
    crate::strings::read_ansi_z(selectors, memory, far_pointer, crate::MAX_WIN16_STRING_BYTES)
}

fn raw_arguments(
    values: &[Win16Argument],
    kinds: &[FormatArgumentKind],
) -> Result<Vec<RawFormatArgument>, Win16Error> {
    if values.len() != kinds.len() { return Err(Win16Error::InvalidRange); }
    let mut result = Vec::new();
    result.try_reserve_exact(values.len()).map_err(|_| Win16Error::OutOfMemory)?;
    for (value, kind) in values.iter().copied().zip(kinds) {
        match (value, kind) {
            (Win16Argument::Word(value), FormatArgumentKind::Word) => {
                result.push(RawFormatArgument::Word(value));
            }
            (Win16Argument::Dword(value), FormatArgumentKind::Dword | FormatArgumentKind::FarString) => {
                result.push(RawFormatArgument::Dword(value));
            }
            _ => return Err(Win16Error::InvalidRange),
        }
    }
    Ok(result)
}

fn read_argument_list(
    far_pointer: u32,
    plan: &FormatPlan,
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Vec<RawFormatArgument>, Win16Error> {
    if plan.arguments().is_empty() { return Ok(Vec::new()); }
    let start = selectors.pointer_from_far(far_pointer)?;
    let mut values = Vec::new();
    values.try_reserve_exact(plan.arguments().len()).map_err(|_| Win16Error::OutOfMemory)?;
    let mut byte_offset = 0_u32;
    for kind in plan.arguments() {
        let width = match kind {
            FormatArgumentKind::Word => 2_usize,
            FormatArgumentKind::Dword | FormatArgumentKind::FarString => 4_usize,
        };
        let end = byte_offset
            .checked_add(width as u32)
            .ok_or(Win16Error::InvalidRange)?;
        // A Win16 stack/list has at most one 64-KiB offset window. Do not let
        // malformed format input wrap a 16-bit list cursor into earlier words.
        if end > 0x1_0000 { return Err(Win16Error::InvalidRange); }
        let pointer = selectors.add_bytes(start, byte_offset)?;
        let mut bytes = [0_u8; 4];
        read_guest_bytes(selectors, memory, pointer, &mut bytes[..width])?;
        let value = if width == 2 {
            RawFormatArgument::Word(u16::from_le_bytes([bytes[0], bytes[1]]))
        } else {
            RawFormatArgument::Dword(u32::from_le_bytes(bytes))
        };
        values.push(value);
        byte_offset = end;
    }
    Ok(values)
}

fn read_guest_bytes(
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
    start: crate::SegmentedPointer,
    output: &mut [u8],
) -> Result<(), Win16Error> {
    let mut pointer = start;
    let mut written = 0;
    while written < output.len() {
        let descriptor = selectors.describe(pointer.selector())?;
        let available = descriptor
            .limit
            .checked_sub(u32::from(pointer.offset()))
            .and_then(|length| length.checked_add(1))
            .and_then(|length| usize::try_from(length).ok())
            .ok_or(Win16Error::InvalidRange)?;
        let chunk = available.min(output.len() - written);
        if chunk == 0 { return Err(Win16Error::InvalidRange); }
        selectors.read(memory, pointer, &mut output[written..written + chunk])?;
        written += chunk;
        if written < output.len() {
            pointer = selectors.add_bytes(
                pointer,
                u32::try_from(chunk).map_err(|_| Win16Error::InvalidRange)?,
            )?;
        }
    }
    Ok(())
}

fn make_request(
    output_far: u32,
    format: &[u8],
    plan: &FormatPlan,
    values: &[RawFormatArgument],
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Win16UserStringFormatRequest, Win16Error> {
    let mut bytes = plan.render(format, values, selectors, memory)?;
    let return_length = u16::try_from(bytes.len()).map_err(|_| Win16Error::InvalidRange)?;
    bytes.try_reserve(1).map_err(|_| Win16Error::OutOfMemory)?;
    bytes.push(0);
    let capacity = u16::try_from(bytes.len()).map_err(|_| Win16Error::InvalidRange)?;
    if usize::from(capacity) > USER_FORMAT_OUTPUT_CAPACITY {
        return Err(Win16Error::InvalidRange);
    }
    let output = checked_output_buffer(output_far, capacity, selectors, memory)?;
    Ok(Win16UserStringFormatRequest { output, bytes, return_length })
}

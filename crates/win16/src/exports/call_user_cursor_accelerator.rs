//! Win16 stack and pointed-data decoding for the USER cursor/accelerator family.

use super::super::Win16ExportId;
use super::super::request::{
    HELP_WINDOW_INFO16_HEADER_BYTES, HELP_WINDOW_INFO16_MIN_BYTES, HelpWindowInfo16HeaderWire,
    MultiKeyHelp16HeaderWire, Win16ApiRequest, Win16HelpData, Win16UserCursorAcceleratorRequest,
};
use super::call_helpers::{
    dword_argument, read_far_string, read_nullable_far_string, word_argument,
};
use crate::{Msg16, SelectorTable, Win16Argument, Win16Error, Win16ResourceName};
use guest_core::GuestMemory;
use zerocopy::FromBytes;

const HELP_KEY: u16 = 0x0101;
const HELP_COMMAND: u16 = 0x0102;
const HELP_PARTIAL_KEY: u16 = 0x0105;
const HELP_MULTI_KEY: u16 = 0x0201;
const HELP_SET_WINDOW_POSITION: u16 = 0x0203;
const HELP_CONTEXT: u16 = 0x0001;
const HELP_QUIT: u16 = 0x0002;
const HELP_INDEX: u16 = 0x0003;
const HELP_ON_HELP: u16 = 0x0004;
const HELP_SET_INDEX: u16 = 0x0005;
const HELP_CONTEXT_POPUP: u16 = 0x0008;
const HELP_FORCE_FILE: u16 = 0x0009;
const MAX_HELP_STRUCTURE_BYTES: usize = 64 * 1024;

pub(super) fn decode(
    id: Win16ExportId,
    arguments: &[Win16Argument],
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Win16ApiRequest, Win16Error> {
    let request = match id {
        Win16ExportId::UserGetCursor => Win16UserCursorAcceleratorRequest::GetCursor,
        Win16ExportId::UserSetCursor => Win16UserCursorAcceleratorRequest::SetCursor {
            cursor: word_argument(arguments, 0)?,
        },
        Win16ExportId::UserShowCursor => Win16UserCursorAcceleratorRequest::ShowCursor {
            show: word_argument(arguments, 0)? != 0,
        },
        Win16ExportId::UserWinHelp => {
            let command = word_argument(arguments, 2)?;
            let raw_data = dword_argument(arguments, 3)?;
            Win16UserCursorAcceleratorRequest::WinHelp {
                window: word_argument(arguments, 0)?,
                help_file: read_nullable_far_string(
                    dword_argument(arguments, 1)?,
                    selectors,
                    memory,
                )?,
                command,
                data: decode_help_data(command, raw_data, selectors, memory)?,
            }
        }
        Win16ExportId::UserLoadAccelerators => {
            let raw_name = dword_argument(arguments, 1)?;
            let name = if raw_name >> 16 == 0 {
                Win16ResourceName::Id(raw_name as u16)
            } else {
                Win16ResourceName::Name(read_far_string(raw_name, selectors, memory)?)
            };
            Win16UserCursorAcceleratorRequest::LoadAccelerators {
                instance: word_argument(arguments, 0)?,
                name,
            }
        }
        Win16ExportId::UserTranslateAccelerator => {
            let raw_message = dword_argument(arguments, 2)?;
            let pointer = selectors.pointer_from_far(raw_message)?;
            let message = Msg16::read_from(selectors, memory, pointer)?;
            Win16UserCursorAcceleratorRequest::TranslateAccelerator {
                window: word_argument(arguments, 0)?,
                accelerator: word_argument(arguments, 1)?,
                message,
            }
        }
        _ => return Err(Win16Error::InvalidRange),
    };
    Ok(Win16ApiRequest::UserCursorAccelerator(request))
}

fn decode_help_data(
    command: u16,
    raw_data: u32,
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Win16HelpData, Win16Error> {
    Ok(match command {
        HELP_CONTEXT | HELP_SET_INDEX | HELP_CONTEXT_POPUP => Win16HelpData::Scalar(raw_data),
        HELP_KEY | HELP_COMMAND | HELP_PARTIAL_KEY => Win16HelpData::String(if raw_data == 0 {
            None
        } else {
            Some(read_far_string(raw_data, selectors, memory)?)
        }),
        HELP_MULTI_KEY => {
            if raw_data == 0 {
                Win16HelpData::NullPointer
            } else {
                read_multi_key(raw_data, selectors, memory)?
            }
        }
        HELP_SET_WINDOW_POSITION => {
            if raw_data == 0 {
                Win16HelpData::NullPointer
            } else {
                read_help_window_info(raw_data, selectors, memory)?
            }
        }
        HELP_QUIT | HELP_INDEX | HELP_ON_HELP | HELP_FORCE_FILE => Win16HelpData::Ignored,
        _ => Win16HelpData::Unsupported { raw_data },
    })
}

fn read_multi_key(
    raw: u32,
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Win16HelpData, Win16Error> {
    let pointer = selectors.pointer_from_far(raw)?;
    let mut header = [0u8; core::mem::size_of::<MultiKeyHelp16HeaderWire>()];
    selectors.read(memory, pointer, &mut header)?;
    let header =
        MultiKeyHelp16HeaderWire::read_from_bytes(&header).map_err(|_| Win16Error::InvalidRange)?;
    let size = usize::from(header.size.get());
    let header_bytes = core::mem::size_of::<MultiKeyHelp16HeaderWire>();
    if !(header_bytes + 1..=MAX_HELP_STRUCTURE_BYTES).contains(&size) {
        return Err(Win16Error::InvalidSize);
    }
    let mut structure = Vec::new();
    structure
        .try_reserve_exact(size)
        .map_err(|_| Win16Error::OutOfMemory)?;
    structure.resize(size, 0);
    selectors.read(memory, pointer, &mut structure)?;
    let phrase = structure
        .get(header_bytes..)
        .ok_or(Win16Error::InvalidRange)?;
    let terminator = phrase
        .iter()
        .position(|byte| *byte == 0)
        .ok_or(Win16Error::InvalidRange)?;
    let phrase = phrase.get(..terminator).ok_or(Win16Error::InvalidRange)?;
    let mut key_phrase = Vec::new();
    key_phrase
        .try_reserve_exact(phrase.len())
        .map_err(|_| Win16Error::OutOfMemory)?;
    key_phrase.extend_from_slice(phrase);
    Ok(Win16HelpData::MultiKey {
        key_list: header.key_list,
        key_phrase,
    })
}

fn read_help_window_info(
    raw: u32,
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Win16HelpData, Win16Error> {
    let pointer = selectors.pointer_from_far(raw)?;
    let mut header_bytes = [0u8; HELP_WINDOW_INFO16_HEADER_BYTES];
    selectors.read(memory, pointer, &mut header_bytes)?;
    let header = HelpWindowInfo16HeaderWire::read_from_bytes(&header_bytes)
        .map_err(|_| Win16Error::InvalidRange)?;
    let declared_size = usize::try_from(header.size.get()).map_err(|_| Win16Error::InvalidSize)?;
    if !(HELP_WINDOW_INFO16_MIN_BYTES..=MAX_HELP_STRUCTURE_BYTES).contains(&declared_size) {
        return Err(Win16Error::InvalidSize);
    }
    let mut structure = Vec::new();
    structure
        .try_reserve_exact(declared_size)
        .map_err(|_| Win16Error::OutOfMemory)?;
    structure.resize(declared_size, 0);
    selectors.read(memory, pointer, &mut structure)?;
    let member_tail = structure
        .get(HELP_WINDOW_INFO16_HEADER_BYTES..)
        .ok_or(Win16Error::InvalidRange)?;
    let terminator = member_tail
        .iter()
        .position(|byte| *byte == 0)
        .ok_or(Win16Error::InvalidRange)?;
    let member_bytes = member_tail
        .get(..terminator)
        .ok_or(Win16Error::InvalidRange)?;
    let mut member = Vec::new();
    member
        .try_reserve_exact(member_bytes.len())
        .map_err(|_| Win16Error::OutOfMemory)?;
    member.extend_from_slice(member_bytes);
    Ok(Win16HelpData::WindowPosition {
        x: header.x.get(),
        y: header.y.get(),
        width: header.width.get(),
        height: header.height.get(),
        max_state: header.max_state.get(),
        member,
    })
}

#[cfg(test)]
#[path = "call_get_cursor_tests.rs"]
mod get_cursor_tests;

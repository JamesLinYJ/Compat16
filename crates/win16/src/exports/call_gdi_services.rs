//! Stack decoding for GDI DC-bound state and object validation exports.

use super::super::Win16ExportId;
use super::{dword_argument, gdi_drawing_calls, read_nullable_far_string, word_argument};
use crate::{SelectorTable, Win16Argument, Win16Error};
use guest_core::GuestMemory;

use super::super::request::{
    Win16FontResourceInput, Win16GdiServicesRequest as Request,
};

pub(super) fn decode(
    export: Win16ExportId,
    arguments: &[Win16Argument],
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Option<Request>, Win16Error> {
    let request = match export {
        Win16ExportId::GdiSetBoundsRect => {
            let rect = gdi_drawing_calls::read_optional_rect(
                dword_argument(arguments, 1)?,
                selectors,
                memory,
            )?;
            Request::SetBoundsRect {
                dc: word_argument(arguments, 0)?,
                rect,
                flags: word_argument(arguments, 2)?,
            }
        }
        Win16ExportId::GdiGetBoundsRect => Request::GetBoundsRect {
            dc: word_argument(arguments, 0)?,
            output: dword_argument(arguments, 1)?,
            flags: word_argument(arguments, 2)?,
        },
        Win16ExportId::GdiSetMapperFlags => Request::SetMapperFlags {
            dc: word_argument(arguments, 0)?,
            flags: dword_argument(arguments, 1)?,
        },
        Win16ExportId::GdiGetAspectRatioFilter => Request::GetAspectRatioFilter {
            dc: word_argument(arguments, 0)?,
        },
        Win16ExportId::GdiGetAspectRatioFilterEx => Request::GetAspectRatioFilterEx {
            dc: word_argument(arguments, 0)?,
            output: dword_argument(arguments, 1)?,
        },
        Win16ExportId::GdiAddFontResource => Request::AddFontResource {
            input: font_resource_input(dword_argument(arguments, 0)?, selectors, memory)?,
        },
        Win16ExportId::GdiRemoveFontResource => Request::RemoveFontResource {
            input: font_resource_input(dword_argument(arguments, 0)?, selectors, memory)?,
        },
        Win16ExportId::GdiGetCharWidth => Request::GetCharWidth {
            dc: word_argument(arguments, 0)?,
            first: word_argument(arguments, 1)?,
            last: word_argument(arguments, 2)?,
            output: dword_argument(arguments, 3)?,
        },
        Win16ExportId::GdiGetCharABCWidths => Request::GetCharAbcWidths {
            dc: word_argument(arguments, 0)?,
            first: word_argument(arguments, 1)?,
            last: word_argument(arguments, 2)?,
            output: dword_argument(arguments, 3)?,
        },
        Win16ExportId::GdiGetFontData => Request::GetFontData {
            dc: word_argument(arguments, 0)?,
            table: dword_argument(arguments, 1)?,
            offset: dword_argument(arguments, 2)?,
            output: dword_argument(arguments, 3)?,
            byte_count: dword_argument(arguments, 4)?,
        },
        Win16ExportId::GdiGetRasterizerCaps => Request::GetRasterizerCaps {
            output: dword_argument(arguments, 0)?,
            byte_count: word_argument(arguments, 1)?,
        },
        Win16ExportId::GdiGetKerningPairs => Request::GetKerningPairs {
            dc: word_argument(arguments, 0)?,
            pair_count: word_argument(arguments, 1)? as i16,
            output: dword_argument(arguments, 2)?,
        },
        Win16ExportId::GdiIsGdiObject => Request::IsGdiObject {
            object: word_argument(arguments, 0)?,
        },
        _ => return Ok(None),
    };
    Ok(Some(request))
}

fn font_resource_input(
    far: u32,
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Win16FontResourceInput, Win16Error> {
    if far == 0 {
        return Ok(Win16FontResourceInput::Null);
    }
    if far >> 16 == 0 {
        // XP NTVDM's WOW16 IAddFontResource/IRemoveFontResource resolve a
        // low-word HINSTANCE to its module filename before entering WOW32.
        return Ok(Win16FontResourceInput::Module(far as u16));
    }
    read_nullable_far_string(far, selectors, memory)
        .map(|path| path.map_or(Win16FontResourceInput::Null, Win16FontResourceInput::Path))
}

#[cfg(test)]
#[path = "call_get_char_width_tests.rs"]
mod char_width_tests;

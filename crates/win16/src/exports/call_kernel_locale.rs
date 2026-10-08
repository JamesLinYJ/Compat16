//! Typed decoder for independent KERNEL locale services.

use super::{Win16ApiRequest, Win16ExportId, call_helpers::word_argument};
use crate::{Win16Argument, Win16Error};

pub(super) fn decode(
    export: Win16ExportId,
    arguments: &[Win16Argument],
) -> Result<Option<Win16ApiRequest>, Win16Error> {
    if export.module().eq_ignore_ascii_case("KERNEL") && export.ordinal() == 207 {
        return Ok(Some(Win16ApiRequest::Libraries(
            super::Win16LibraryRequest::CodePage(
                super::Win16LibraryCodePageRequest::IsDbcsLeadByte {
                    value: word_argument(arguments, 0)? as u8,
                },
            ),
        )));
    }
    Ok(None)
}

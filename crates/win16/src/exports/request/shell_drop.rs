//! Typed Windows 3.1 SHELL drag/drop and documented Windows 4.x format-drive ABI.

use crate::{Win16Argument, Win16Error};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16ShellDropRequest {
    DragAcceptFiles { window: u16, accept: u16 },
    DragQueryFile { drop: u16, index: u16, file_name_far: u32, capacity: u16 },
    DragFinish { drop: u16 },
    DragQueryPoint { drop: u16, point_far: u32 },
    FormatDrive { owner: u16, drive: u16, format_id: u16, options: u16 },
}

pub fn decode_shell_drop_export(
    ordinal: u16,
    arguments: &[Win16Argument],
) -> Result<Win16ShellDropRequest, Win16Error> {
    let word = |index| match arguments.get(index) {
        Some(Win16Argument::Word(value)) => Ok(*value),
        _ => Err(Win16Error::InvalidRange),
    };
    let far = |index| match arguments.get(index) {
        Some(Win16Argument::Dword(value)) => Ok(*value),
        _ => Err(Win16Error::InvalidRange),
    };
    match ordinal {
        9 => Ok(Win16ShellDropRequest::DragAcceptFiles {
            window: word(0)?, accept: word(1)?,
        }),
        11 => Ok(Win16ShellDropRequest::DragQueryFile {
            drop: word(0)?, index: word(1)?, file_name_far: far(2)?, capacity: word(3)?,
        }),
        12 => Ok(Win16ShellDropRequest::DragFinish { drop: word(0)? }),
        13 => Ok(Win16ShellDropRequest::DragQueryPoint {
            drop: word(0)?, point_far: far(1)?,
        }),
        400 => Ok(Win16ShellDropRequest::FormatDrive {
            owner: word(0)?, drive: word(1)?, format_id: word(2)?, options: word(3)?,
        }),
        _ => Err(Win16Error::InvalidRange),
    }
}

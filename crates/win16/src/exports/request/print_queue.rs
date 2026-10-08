//! Owned arguments for the GDI priority-queue exports in PRINT.H.

use crate::{Win16Argument, Win16Error};

/// Guest values for the six GDI printer-driver priority-queue APIs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16PrintQueueRequest {
    Create { capacity: i16 },
    Min { queue: u16 },
    Extract { queue: u16 },
    Insert { queue: u16, tag: i16, priority: i16 },
    Resize { queue: u16, size_change: i16 },
    Delete { queue: u16 },
}

/// Decode the known GDI priority-queue exports by their Windows 3.1 ordinals.
pub fn decode_print_queue_export(
    ordinal: u16,
    arguments: &[Win16Argument],
) -> Result<Win16PrintQueueRequest, Win16Error> {
    let request = match ordinal {
        230 => Win16PrintQueueRequest::Create {
            capacity: signed_word(arguments, 0)?,
        },
        231 => Win16PrintQueueRequest::Min {
            queue: word(arguments, 0)?,
        },
        232 => Win16PrintQueueRequest::Extract {
            queue: word(arguments, 0)?,
        },
        233 => Win16PrintQueueRequest::Insert {
            queue: word(arguments, 0)?,
            tag: signed_word(arguments, 1)?,
            priority: signed_word(arguments, 2)?,
        },
        234 => Win16PrintQueueRequest::Resize {
            queue: word(arguments, 0)?,
            size_change: signed_word(arguments, 1)?,
        },
        235 => Win16PrintQueueRequest::Delete {
            queue: word(arguments, 0)?,
        },
        _ => return Err(Win16Error::InvalidRange),
    };
    Ok(request)
}

fn word(arguments: &[Win16Argument], index: usize) -> Result<u16, Win16Error> {
    match arguments.get(index) {
        Some(Win16Argument::Word(value)) => Ok(*value),
        _ => Err(Win16Error::InvalidRange),
    }
}

fn signed_word(arguments: &[Win16Argument], index: usize) -> Result<i16, Win16Error> {
    word(arguments, index).map(|value| value as i16)
}

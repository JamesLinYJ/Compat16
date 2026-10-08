//! Decoder adapter for the GDI priority-queue export family.

use crate::{Win16Argument, Win16Error};

use super::request::{Win16PrintQueueRequest, decode_print_queue_export};

pub(super) fn decode(
    ordinal: u16,
    arguments: &[Win16Argument],
) -> Result<Option<Win16PrintQueueRequest>, Win16Error> {
    if (230..=235).contains(&ordinal) {
        decode_print_queue_export(ordinal, arguments).map(Some)
    } else {
        Ok(None)
    }
}

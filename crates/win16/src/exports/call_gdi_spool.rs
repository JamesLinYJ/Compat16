//! GDI PRINT.H spool-job stack decoding.

use super::super::Win16ExportId;
use super::super::request::Win16GdiSpoolRequest as Request;
use super::{
    dword_argument, read_far_bytes, read_far_string, read_nullable_far_string, word_argument,
};
use crate::{SelectorTable, Win16Error};
use guest_core::GuestMemory;

pub(super) fn decode(
    export: Win16ExportId,
    arguments: &[crate::Win16Argument],
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Option<Request>, Win16Error> {
    let request = match export {
        Win16ExportId::GdiOpenJob => Request::OpenJob {
            output_target: read_far_string(dword_argument(arguments, 0)?, selectors, memory)?,
            document_name: read_far_string(dword_argument(arguments, 1)?, selectors, memory)?,
            legacy_argument: word_argument(arguments, 2)?,
        },
        Win16ExportId::GdiWriteSpool => {
            let byte_count = word_argument(arguments, 2)? as i16;
            let bytes = if byte_count > 0 {
                read_far_bytes(
                    dword_argument(arguments, 1)?,
                    byte_count as usize,
                    selectors,
                    memory,
                )?
            } else {
                Vec::new()
            };
            Request::WriteSpool {
                job: word_argument(arguments, 0)?,
                byte_count,
                bytes,
            }
        }
        Win16ExportId::GdiCloseJob => Request::CloseJob {
            job: word_argument(arguments, 0)?,
        },
        Win16ExportId::GdiDeleteJob => Request::DeleteJob {
            job: word_argument(arguments, 0)?,
            legacy_argument: word_argument(arguments, 1)? as i16,
        },
        Win16ExportId::GdiStartSpoolPage => Request::StartSpoolPage {
            job: word_argument(arguments, 0)?,
        },
        Win16ExportId::GdiEndSpoolPage => Request::EndSpoolPage {
            job: word_argument(arguments, 0)?,
        },
        Win16ExportId::GdiSetEnvironment => {
            let capacity = word_argument(arguments, 2)?;
            let environment = dword_argument(arguments, 1)?;
            // The SDK count is the copy length. A zero count or a null
            // pointer deletes or fails without treating the pointer as bytes.
            let environment = if capacity == 0 || environment == 0 {
                None
            } else {
                Some(read_far_bytes(
                    environment,
                    usize::from(capacity),
                    selectors,
                    memory,
                )?)
            };
            Request::SetEnvironment {
                port: read_nullable_far_string(dword_argument(arguments, 0)?, selectors, memory)?,
                environment,
                capacity,
            }
        }
        Win16ExportId::GdiGetEnvironment => Request::GetEnvironment {
            port: read_nullable_far_string(dword_argument(arguments, 0)?, selectors, memory)?,
            environment: dword_argument(arguments, 1)?,
            capacity: word_argument(arguments, 2)?,
        },
        Win16ExportId::GdiQueryAbort => Request::QueryAbort {
            dc: word_argument(arguments, 0)?,
            code: word_argument(arguments, 1)? as i16,
        },
        _ => return Ok(None),
    };
    Ok(Some(request))
}

#[cfg(test)]
#[path = "call_gdi_spool_tests.rs"]
mod tests;

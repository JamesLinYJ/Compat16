//! Bounded Win16 Escape queries. Printing commands and private driver escapes
//! are intentionally absent; unsupported codes return the documented zero.

use super::*;
use crate::Win16EscapeQuery as Query;
use win16_abi::Access;

impl Win16State {
    pub(super) fn gdi_escape(
        &mut self,
        memory: &mut Memory,
        dc: u16,
        escape: i16,
        input_size: i16,
        input: u32,
        output: u32,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let Some(query) = escape_query(escape) else {
            return Ok(0);
        };
        let Some(dc) = self.guest_gdi.dc(dc) else {
            return Ok(0);
        };
        if query == Query::QuerySupport {
            // SDK 3.1 QUERYESCSUPPORT takes sizeof(int) == 2, not the host's
            // four-byte int. It has no output, so never inspect `output`.
            if input_size != 2 || input == 0 || (input as u16) == u16::MAX {
                return Ok(0);
            }
            let pointer = self
                .selectors
                .pointer_from_far(input)
                .map_err(crate::runtime_error)?;
            let mut bytes = [0; 2];
            self.selectors
                .read(memory, pointer, &mut bytes)
                .map_err(crate::runtime_error)?;
            let Some(query) = escape_query(i16::from_le_bytes(bytes)) else {
                return Ok(0);
            };
            return match host.win16_gdi_device(Operation::QueryEscapeSupport { dc, query })? {
                HostResult::Bool(supported) => Ok(u32::from(supported)),
                _ => Err(wrong_device_result("Escape QUERYESCSUPPORT")),
            };
        }
        // These three SDK queries have no input and write one POINT16. A FAR
        // pointer must fit its segment; it is not a huge pointer. Preflight
        // the complete writable range before even a read-only host query.
        if input_size != 0 || output == 0 || usize::from(output as u16) > 0x1_0000 - 4 {
            return Ok(0);
        }
        let target = self
            .selectors
            .pointer_from_far(output)
            .map_err(crate::runtime_error)?;
        self.selectors
            .translate(target, Access::Write, 4, memory)
            .map_err(crate::runtime_error)?;
        // This typed host path performs read-only queries and cannot execute
        // guest callbacks or remap selectors before this prepared commit.
        let prepared = self.prepare_text_write(memory, target, 4)?;
        match host.win16_gdi_device(Operation::EscapeQuery { dc, query })? {
            HostResult::Point { success: false, .. } => Ok(0),
            HostResult::Point {
                success: true,
                x,
                y,
            } => {
                let (Ok(x), Ok(y)) = (i16::try_from(x), i16::try_from(y)) else {
                    return Ok(0);
                };
                let mut bytes = [0; 4];
                bytes[..2].copy_from_slice(&x.to_le_bytes());
                bytes[2..].copy_from_slice(&y.to_le_bytes());
                prepared.commit(memory, &bytes)?;
                Ok(1)
            }
            _ => Err(wrong_device_result("Escape POINT query")),
        }
    }
}

fn escape_query(escape: i16) -> Option<Query> {
    match escape {
        8 => Some(Query::QuerySupport),
        12 => Some(Query::PhysicalPageSize),
        13 => Some(Query::PrintingOffset),
        14 => Some(Query::ScalingFactor),
        _ => None,
    }
}

#[cfg(test)]
#[path = "../win16_gdi_escape_tests.rs"]
mod tests;

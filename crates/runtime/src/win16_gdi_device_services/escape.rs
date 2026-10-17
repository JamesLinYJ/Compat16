//! Bounded Win16 Escape queries and the print-job subset.
//!
//! SETABORTPROC, PASSTHROUGH, NEXTBAND, SETCOPYCOUNT, and private driver
//! escapes stay unimplemented and return zero. No guest pointer is passed to
//! native Escape.

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
        if let Some(command) = print_command(query) {
            // Printing failure is SP_ERROR. Zero remains the unimplemented code.
            let Some(_) = self.guest_gdi.dc(dc) else {
                return Ok(SP_ERROR16);
            };
            return self.escape_print(memory, dc, command, input_size, input, host);
        }
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

    /// Windows 3.1 STARTDOC carries a counted document name and ignores output.
    /// NEWFRAME, ENDDOC, and ABORTDOC ignore both pointers. Win32 split the
    /// page boundary into StartPage/EndPage, which the 3.1 header does not
    /// describe: STARTDOC and NEWFRAME leave a page open, and ENDDOC closes
    /// that page before ending the job.
    fn escape_print(
        &mut self,
        memory: &Memory,
        dc: u16,
        command: PrintCommand,
        input_size: i16,
        input: u32,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        match command {
            PrintCommand::Start => {
                let Some(document_name) = self.start_doc_name(memory, input_size, input)? else {
                    return Ok(SP_ERROR16);
                };
                let started = self.start_doc(
                    dc,
                    Some(DocInfo16 {
                        document_name: Some(document_name),
                        output: None,
                    }),
                    host,
                )?;
                if !positive_escape(started) {
                    return Ok(started);
                }
                let page = match self.print(PrintOperation::StartPage, dc, host) {
                    Ok(status) if positive_escape(status) => return Ok(started),
                    Ok(status) => status,
                    Err(error) => {
                        self.print(PrintOperation::AbortDocument, dc, host)?;
                        return Err(error);
                    }
                };
                self.print(PrintOperation::AbortDocument, dc, host)?;
                Ok(page)
            }
            PrintCommand::NewFrame => {
                let ended = self.print(PrintOperation::EndPage, dc, host)?;
                if !positive_escape(ended) {
                    return Ok(ended);
                }
                self.print(PrintOperation::StartPage, dc, host)
            }
            PrintCommand::End => {
                let ended = self.print(PrintOperation::EndPage, dc, host)?;
                if !positive_escape(ended) {
                    return Ok(ended);
                }
                self.print(PrintOperation::EndDocument, dc, host)
            }
            PrintCommand::Abort => self.print(PrintOperation::AbortDocument, dc, host),
        }
    }

    fn start_doc_name(
        &self,
        memory: &Memory,
        input_size: i16,
        input: u32,
    ) -> Result<Option<Vec<u8>>, RuntimeError> {
        // nCount is the byte count. Selector zero is the Win16 null pointer.
        if input_size <= 0 || input >> 16 == 0 {
            return Ok(None);
        }
        let length = usize::from(input_size as u16);
        let offset = usize::from(input as u16);
        let Some(end) = offset.checked_add(length) else {
            return Ok(None);
        };
        if end > 0x1_0000 {
            return Ok(None);
        }
        let pointer = self
            .selectors
            .pointer_from_far(input)
            .map_err(crate::runtime_error)?;
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(length).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve Win16 STARTDOC name",
                error,
            )
        })?;
        bytes.resize(length, 0);
        self.selectors
            .read(memory, pointer, &mut bytes)
            .map_err(crate::runtime_error)?;
        // Accept either lstrlen or lstrlen+1. A NUL anywhere earlier is not a name.
        let terminator = bytes
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(bytes.len());
        if terminator + 1 < bytes.len() {
            return Ok(None);
        }
        bytes.truncate(terminator);
        Ok(Some(bytes))
    }
}

enum PrintCommand {
    Start,
    NewFrame,
    End,
    Abort,
}

fn print_command(query: Query) -> Option<PrintCommand> {
    match query {
        Query::StartDocument => Some(PrintCommand::Start),
        Query::NewFrame => Some(PrintCommand::NewFrame),
        Query::EndDocument => Some(PrintCommand::End),
        Query::AbortDocument => Some(PrintCommand::Abort),
        Query::QuerySupport
        | Query::PhysicalPageSize
        | Query::PrintingOffset
        | Query::ScalingFactor => None,
    }
}

fn positive_escape(status: u32) -> bool {
    i16::try_from(status).ok().is_some_and(|value| value > 0)
}

fn escape_query(escape: i16) -> Option<Query> {
    match escape {
        8 => Some(Query::QuerySupport),
        12 => Some(Query::PhysicalPageSize),
        13 => Some(Query::PrintingOffset),
        14 => Some(Query::ScalingFactor),
        10 => Some(Query::StartDocument),
        1 => Some(Query::NewFrame),
        11 => Some(Query::EndDocument),
        2 => Some(Query::AbortDocument),
        _ => None,
    }
}

#[cfg(test)]
#[path = "../win16_gdi_escape_tests.rs"]
mod tests;

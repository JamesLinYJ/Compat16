//! Bounded Win16 Escape queries and the print-job subset.
//!
//! SETABORTPROC installs the same guest abort procedure as `SetAbortProc`.
//! Its input dword is the procedure address and is not passed to native
//! Escape. NEXTBAND simulates a non-banding printer: the first call of a page
//! returns the printable page, and the next call ejects that page and returns
//! an empty rectangle. PASSTHROUGH, SETCOPYCOUNT, and private driver escapes
//! stay unimplemented and return zero.

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
        if escape == super::super::print_abort::SET_ABORT_PROC_ESCAPE {
            // The input dword is the AbortProc address, not a guest buffer.
            return self.set_abort_proc(memory, dc, input);
        }
        if escape == NEXT_BAND_ESCAPE {
            // nCount and lpInData are unused. The rectangle is lpvOutData.
            return self.escape_next_band(memory, dc, output, host);
        }
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
            if i16::from_le_bytes(bytes) == super::super::print_abort::SET_ABORT_PROC_ESCAPE {
                return Ok(1);
            }
            if i16::from_le_bytes(bytes) == NEXT_BAND_ESCAPE {
                return match host.win16_gdi_device(Operation::QueryEscapeSupport {
                    dc,
                    query: Query::PrintablePage,
                })? {
                    HostResult::Bool(supported) => Ok(u32::from(supported)),
                    _ => Err(wrong_device_result("Escape QUERYESCSUPPORT")),
                };
            }
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
                    Ok(status) if positive_escape(status) => {
                        self.guest_gdi.clear_next_band(dc);
                        return Ok(started);
                    }
                    Ok(status) => status,
                    Err(error) => {
                        self.print(PrintOperation::AbortDocument, dc, host)?;
                        self.guest_gdi.clear_next_band(dc);
                        return Err(error);
                    }
                };
                self.print(PrintOperation::AbortDocument, dc, host)?;
                self.guest_gdi.clear_next_band(dc);
                Ok(page)
            }
            PrintCommand::NewFrame => {
                // A completed NEXTBAND already ejected the page. Closing it
                // again would emit a second page.
                if self.guest_gdi.next_band_ejected(dc) {
                    let started = self.print(PrintOperation::StartPage, dc, host)?;
                    if positive_escape(started) {
                        self.guest_gdi.clear_next_band(dc);
                    }
                    return Ok(started);
                }
                let ended = self.print(PrintOperation::EndPage, dc, host)?;
                if !positive_escape(ended) {
                    return Ok(ended);
                }
                let started = self.print(PrintOperation::StartPage, dc, host)?;
                if positive_escape(started) {
                    self.guest_gdi.clear_next_band(dc);
                }
                Ok(started)
            }
            PrintCommand::End => {
                if !self.guest_gdi.next_band_ejected(dc) {
                    let ended = self.print(PrintOperation::EndPage, dc, host)?;
                    if !positive_escape(ended) {
                        return Ok(ended);
                    }
                }
                let closed = self.print(PrintOperation::EndDocument, dc, host)?;
                if positive_escape(closed) {
                    self.guest_gdi.clear_next_band(dc);
                }
                Ok(closed)
            }
            PrintCommand::Abort => {
                let status = self.print(PrintOperation::AbortDocument, dc, host)?;
                if positive_escape(status) {
                    self.guest_gdi.clear_next_band(dc);
                }
                Ok(status)
            }
        }
    }

    /// Windows 3.1 `NEXTBAND` for a driver that does not band.
    ///
    /// The first call of a page writes the printable page, `(0, 0, HORZRES,
    /// VERTRES)`, in device units. The next call ejects that page and writes
    /// an empty rectangle. A later call is the first band of the next page.
    /// Both successful calls return a positive value. A coordinate outside
    /// `-32768..=32767`, or a non-positive extent, fails and leaves the guest
    /// rectangle unchanged. `nCount` and `lpInData` are not read.
    fn escape_next_band(
        &mut self,
        memory: &mut Memory,
        dc: u16,
        output: u32,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let Some(native) = self.guest_gdi.dc(dc) else {
            return Ok(SP_ERROR16);
        };
        let Some(prepared) = self.prepare_band_rect(memory, output)? else {
            return Ok(0);
        };
        if self.guest_gdi.next_band_open(dc) {
            let ended = self.print(PrintOperation::EndPage, dc, host)?;
            if !positive_escape(ended) {
                return Ok(ended);
            }
            prepared.commit(memory, &[0; 8])?;
            self.guest_gdi.note_next_band_ejected(dc);
            return Ok(ended);
        }
        if self.guest_gdi.next_band_ejected(dc) || self.guest_gdi.print_document_open(dc) {
            let Some((width, height)) = self.printable_band(native, host)? else {
                return Ok(0);
            };
            if self.guest_gdi.next_band_ejected(dc) {
                let started = self.print(PrintOperation::StartPage, dc, host)?;
                if !positive_escape(started) {
                    return Ok(started);
                }
            }
            prepared.commit(memory, &band_bytes(width, height))?;
            self.guest_gdi.note_next_band_open(dc);
            return Ok(1);
        }
        match host.win16_gdi_device(Operation::QueryEscapeSupport {
            dc: native,
            query: Query::PrintablePage,
        })? {
            HostResult::Bool(true) => Ok(SP_ERROR16),
            HostResult::Bool(false) => Ok(0),
            _ => Err(wrong_device_result("Escape NEXTBAND")),
        }
    }

    fn prepare_band_rect(
        &self,
        memory: &Memory,
        output: u32,
    ) -> Result<Option<super::super::text_memory::PreparedTextWrite>, RuntimeError> {
        // A Win16 RECT is four signed words and must fit in one selector.
        if output == 0 || usize::from(output as u16) > 0x1_0000 - 8 {
            return Ok(None);
        }
        let target = self
            .selectors
            .pointer_from_far(output)
            .map_err(crate::runtime_error)?;
        self.selectors
            .translate(target, Access::Write, 8, memory)
            .map_err(crate::runtime_error)?;
        self.prepare_text_write(memory, target, 8).map(Some)
    }

    fn printable_band(
        &self,
        dc: crate::Win16HostDc,
        host: &mut impl RuntimeHost,
    ) -> Result<Option<(i16, i16)>, RuntimeError> {
        match host.win16_gdi_device(Operation::EscapeQuery {
            dc,
            query: Query::PrintablePage,
        })? {
            HostResult::Point { success: false, .. } => Ok(None),
            HostResult::Point {
                success: true,
                x,
                y,
            } => {
                let (Ok(x), Ok(y)) = (i16::try_from(x), i16::try_from(y)) else {
                    return Ok(None);
                };
                if x <= 0 || y <= 0 {
                    return Ok(None);
                }
                Ok(Some((x, y)))
            }
            _ => Err(wrong_device_result("Escape NEXTBAND")),
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
        | Query::ScalingFactor
        | Query::PrintablePage => None,
    }
}

fn positive_escape(status: u32) -> bool {
    i16::try_from(status).ok().is_some_and(|value| value > 0)
}

/// Application `NEXTBAND`. The driver `Control` number is the same value.
const NEXT_BAND_ESCAPE: i16 = 3;

fn band_bytes(width: i16, height: i16) -> [u8; 8] {
    let mut bytes = [0; 8];
    bytes[4..6].copy_from_slice(&width.to_le_bytes());
    bytes[6..8].copy_from_slice(&height.to_le_bytes());
    bytes
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

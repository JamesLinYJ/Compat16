//! Explicit Win16 I/O diagnostics with bounded or complete disk transcripts.

use std::{collections::VecDeque, fs::File, io::{self, BufWriter, Write}, path::Path, time::Instant};

const MAX_ROWS: usize = 4096;
// The startup transcript is bounded separately from recent observations, so
// an interactive session retains evidence even after its startup budget ends.
const RECENT_ROWS: usize = 256;
const RECENT_BYTES: usize = 128 * 1024;

mod startup;

pub(super) struct Win16IoTrace {
    file: BufWriter<File>,
    complete: bool,
    started: Instant,
    rows: usize,
    service_boundaries: Vec<bool>,
    overflowed_service_depth: usize,
    reserved_service_returns: usize,
    recent: VecDeque<(u64, String)>,
    recent_bytes: usize,
    observed: u64,
    startup: startup::StartupProgress,
}

impl Win16IoTrace {
    pub(super) fn create(path: &Path, complete: bool) -> io::Result<Self> {
        Ok(Self {
            file: BufWriter::new(File::create_new(path)?),
            complete,
            started: Instant::now(),
            rows: 0,
            service_boundaries: Vec::with_capacity(MAX_ROWS),
            overflowed_service_depth: 0,
            reserved_service_returns: 0,
            recent: VecDeque::new(),
            recent_bytes: 0,
            observed: 0,
            startup: startup::StartupProgress::default(),
        })
    }

    pub(super) const fn is_full(&self) -> bool { self.rows >= MAX_ROWS }
    pub(super) const fn is_complete(&self) -> bool { self.complete }

    pub(super) fn native_pixel(
        &mut self, dc: u64, x: i32, y: i32, kind: u32,
        bitmap: Option<(i32, i32, i32, u16, u16, bool)>,
    ) -> io::Result<()> {
        if !self.complete { return Ok(()); }
        let elapsed = self.started.elapsed().as_micros();
        write_complete_row(&mut self.file, self.observed, &format_args!(
            "native-pixel dc={dc} x={x} y={y} dc-kind={kind} bitmap={bitmap:?} elapsed-us={elapsed}"))?;
        self.observed = self.observed.saturating_add(1);
        Ok(())
    }

    pub(super) fn record(&mut self, event: &runtime::Win16IoEvent<'_>) -> io::Result<()> {
        if self.complete {
            // Flush each event before execution continues so a blocked native
            // call still leaves its entry row when the process tree is killed.
            // Monotonic elapsed time distinguishes dispatch latency from the
            // guest execution between calls. Keep the event/sequence prefix
            // intact for existing readers and flush the entry before dispatch.
            let elapsed = self.started.elapsed().as_micros();
            write_complete_row(&mut self.file, self.observed,
                &format_args!("{event} elapsed-us={elapsed}"))?;
            self.observed = self.observed.saturating_add(1);
            return Ok(());
        }
        let persist_startup = self.startup.observe(event);
        let mut text = event.to_string();
        if text.len() > RECENT_BYTES {
            let mut end = RECENT_BYTES;
            while !text.is_char_boundary(end) { end -= 1; }
            text.truncate(end);
        }
        while self.recent.len() >= RECENT_ROWS || self.recent_bytes + text.len() > RECENT_BYTES {
            if let Some((_, removed)) = self.recent.pop_front() {
                self.recent_bytes -= removed.len();
            } else { break; }
        }
        self.recent_bytes += text.len();
        self.recent.push_back((self.observed, text));
        self.observed = self.observed.saturating_add(1);
        if self.is_full() {
            // Long initialization can exhaust the prefix before GetMessage.
            // Publish real late startup/probe events while the process is
            // still alive; a forced stop cannot run Drop to save this tail.
            // At most one message-loop entry and eight validated WM_NULL
            // returns trigger a live flush, each bounded by RECENT_BYTES.
            if persist_startup { self.flush_recent()?; }
            return Ok(());
        }
        let service_enter = matches!(
            event,
            runtime::Win16IoEvent::ServiceBoundary {
                stage: runtime::Win16ServiceBoundaryStage::DispatchEnter,
                ..
            }
        );
        let service_exit = matches!(
            event,
            runtime::Win16IoEvent::ServiceBoundary {
                stage: runtime::Win16ServiceBoundaryStage::DispatchReturn
                    | runtime::Win16ServiceBoundaryStage::DispatchError,
                ..
            }
        );

        if service_enter {
            if self.overflowed_service_depth != 0 || self.service_boundaries.len() >= MAX_ROWS {
                self.overflowed_service_depth = self.overflowed_service_depth.saturating_add(1);
                return Ok(());
            }
            if self.rows + self.reserved_service_returns + 2 > MAX_ROWS {
                if self.reserved_service_returns != 0 {
                    // A nested call cannot fit without stealing an outer
                    // return row; suppress both sides of this nested pair.
                    self.service_boundaries.push(false);
                    return Ok(());
                }
                // Do not start a final call when its leave row cannot fit.
                self.rows = MAX_ROWS;
                writeln!(self.file, "trace limit reached ({MAX_ROWS} operations; next service boundary omitted to preserve pairing)")?;
                self.file.flush()?;
                return Ok(());
            }
            self.write_row(event)?;
            self.service_boundaries.push(true);
            self.reserved_service_returns += 1;
            return Ok(());
        }

        if service_exit {
            if self.overflowed_service_depth != 0 {
                self.overflowed_service_depth -= 1;
                return Ok(());
            }
            if let Some(logged_enter) = self.service_boundaries.pop() {
                if !logged_enter {
                    return Ok(());
                }
                self.reserved_service_returns -= 1;
            }
        } else if self.rows + self.reserved_service_returns + 1 > MAX_ROWS {
            // Keep any already written service entry closable even when the
            // remaining budget is consumed by nested I/O observations.
            return Ok(());
        }

        self.write_row(event)
    }

    fn write_row(&mut self, event: &runtime::Win16IoEvent<'_>) -> io::Result<()> {
        writeln!(self.file, "#{:04} {event}", self.rows)?;
        self.file.flush()?;
        self.rows += 1;
        if self.is_full() {
            writeln!(self.file, "trace limit reached ({MAX_ROWS} operations)")?;
            self.file.flush()?;
        }
        Ok(())
    }

    pub(super) fn flush_recent(&mut self) -> io::Result<()> {
        if self.recent.is_empty() { return self.file.flush(); }
        writeln!(self.file, "recent observations (bounded tail; first service may be partial):")?;
        while let Some((sequence, text)) = self.recent.front() {
            writeln!(self.file, "@{sequence} {text}")?;
            self.recent_bytes -= text.len();
            self.recent.pop_front();
        }
        self.file.flush()
    }
}

impl Drop for Win16IoTrace {
    fn drop(&mut self) {
        // Preserve the tail on early error returns as well as normal shutdown.
        // Explicit completion reports write failures; Drop cannot alter exit.
        let _ = self.flush_recent();
    }
}

fn write_complete_row(
    writer: &mut impl Write,
    sequence: u64,
    event: &impl std::fmt::Display,
) -> io::Result<()> {
    writeln!(writer, "@{sequence} {event}")?;
    writer.flush()
}

#[cfg(test)]
#[path = "win16_io_trace_tests.rs"]
mod diagnostics_tests;

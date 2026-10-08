//! Bounded opt-in DOS INT 21h request/return trace.

use std::fs::File;
use std::io::{self, Write};
use std::path::Path;
use runtime::GuestRegisters;

const MAX_ROWS: usize = 4096;

pub(super) struct DosServiceTrace {
    file: File,
    rows: usize,
}

impl DosServiceTrace {
    pub(super) fn create(path: &Path) -> io::Result<Self> {
        Ok(Self { file: File::create_new(path)?, rows: 0 })
    }

    pub(super) const fn is_full(&self) -> bool { self.rows >= MAX_ROWS }

    pub(super) fn record(
        &mut self,
        instruction_count: u64,
        before: &GuestRegisters,
        after: &GuestRegisters,
    ) -> io::Result<()> {
        if self.is_full() { return Ok(()); }
        writeln!(self.file,
            "#{instruction_count:012} INT21 request AX={:04X} BX={:04X} CX={:04X} DX={:04X} DS={:04X} ES={:04X} SI={:04X} DI={:04X} return AX={:04X} BX={:04X} CX={:04X} DX={:04X} ES={:04X} FLAGS={:08X}",
            before.ax(), before.bx(), before.cx(), before.dx(), before.ds, before.es, before.si(), before.di(),
            after.ax(), after.bx(), after.cx(), after.dx(), after.es, after.eflags,
        )?;
        self.file.flush()?;
        self.rows += 1;
        Ok(())
    }
}

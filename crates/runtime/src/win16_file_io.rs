//! Win16 huge-file transfers and huge-memory copy over checked guest selectors.

use guest_core::memory::Memory;

use super::Win16State;
use crate::{DiagnosticKind as Kind, RuntimeError, RuntimeHost, Win16IoEvent};

impl Win16State {
    /// Read one Win16 file transfer. The complete guest output span is checked
    /// before the host file position can advance.
    pub(super) fn read_file(
        &mut self,
        file: u16,
        buffer: u32,
        count: i32,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let result = self.read_file_checked(file, buffer, count, memory, host);
        host.observe_win16_io(&Win16IoEvent::Transfer {
            operation: "read", file, buffer, requested: count,
            result: result.as_ref().ok().copied(),
        });
        result
    }

    fn read_file_checked(
        &mut self, file: u16, buffer: u32, count: i32,
        memory: &mut Memory, host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        if let Some(owner) = self.tasks.current()
            && self.reject_network_print_hfile_io(owner, file)
        {
            return Ok(u32::MAX);
        }
        let Some(host_file) = self.files.get(&file).copied() else {
            return Ok(u32::MAX);
        };
        if count < 0 {
            return Ok(u32::MAX);
        }

        // _lread/_hread with a zero count still go through the native file
        // service, but never inspect the caller's FAR buffer.
        if count == 0 {
            return match host.win16_file_read(host_file, 0)? {
                Some(bytes) if bytes.is_empty() => Ok(0),
                Some(_) => Err(RuntimeError::new(Kind::InternalInvariant,
                    "host Win16 zero-count file read returned data")),
                None => Ok(u32::MAX),
            };
        }

        let length = count as usize;
        let pointer = self.selectors.pointer_from_far(buffer).map_err(crate::runtime_error)?;
        // Capture the output ranges and rollback bytes before the native read
        // advances the file position; commit then needs no large allocation.
        let output = self.prepare_text_write(memory, pointer, length)?;

        let Some(bytes) = host.win16_file_read(host_file, length as u32)? else {
            return Ok(u32::MAX);
        };
        if bytes.len() > length {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "host Win16 file read exceeded the requested byte count"));
        }
        output.commit(memory, &bytes)?;
        Ok(bytes.len() as u32)
    }

    /// Write one Win16 file transfer. The complete guest input span is copied
    /// before the host file can be modified; an empty transfer delegates the
    /// Win16 zero-length truncation operation to the host adapter.
    pub(super) fn write_file(
        &mut self,
        file: u16,
        buffer: u32,
        count: i32,
        memory: &Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let result = self.write_file_checked(file, buffer, count, memory, host);
        host.observe_win16_io(&Win16IoEvent::Transfer {
            operation: "write", file, buffer, requested: count,
            result: result.as_ref().ok().copied(),
        });
        result
    }

    fn write_file_checked(
        &mut self, file: u16, buffer: u32, count: i32,
        memory: &Memory, host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        if let Some(owner) = self.tasks.current()
            && self.network_print_hfile_is_owned(owner, file)
        {
            if count < 0 {
                return Ok(u32::MAX);
            }
            let bytes = if count == 0 {
                Vec::new()
            } else {
                let pointer = self.selectors.pointer_from_far(buffer).map_err(crate::runtime_error)?;
                self.read_text_bytes(memory, pointer, count as usize)?
            };
            return Ok(self.write_network_print_hfile(owner, file, &bytes, host)?
                .unwrap_or(u32::MAX));
        }
        let Some(host_file) = self.files.get(&file).copied() else {
            return Ok(u32::MAX);
        };
        if count < 0 {
            return Ok(u32::MAX);
        }

        let bytes = if count == 0 {
            Vec::new()
        } else {
            let pointer = self.selectors.pointer_from_far(buffer).map_err(crate::runtime_error)?;
            self.read_text_bytes(memory, pointer, count as usize)?
        };
        match host.win16_file_write(host_file, &bytes)? {
            Some(written) if written <= bytes.len() as u32 => Ok(written),
            Some(_) => Err(RuntimeError::new(Kind::InternalInvariant,
                "host Win16 file write exceeded the supplied byte count")),
            None => Ok(u32::MAX),
        }
    }

    pub(super) fn seek_file(
        &self, file: u16, offset: i32, origin: u16, host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let result = if self.tasks.current()
            .is_some_and(|owner| self.reject_network_print_hfile_io(owner, file))
        {
            Ok(u32::MAX)
        } else {
            match self.files.get(&file).copied() {
                Some(native) => host.win16_file_seek(native, offset, origin)
                    .map(|position| position.map_or(u32::MAX, |position| position as u32)),
                None => Ok(u32::MAX),
            }
        };
        host.observe_win16_io(&Win16IoEvent::Seek {
            operation: "seek", file, offset, origin, result: result.as_ref().ok().copied(),
        });
        result
    }

    /// Copy bytes between huge guest pointers. Snapshotting the entire source
    /// before writing gives the expected overlap-safe result while keeping all
    /// addresses inside the simulated guest memory.
    pub(super) fn copy_huge_memory(
        &self,
        destination: u32,
        source: u32,
        count: i32,
        memory: &mut Memory,
    ) -> Result<(), RuntimeError> {
        if count < 0 {
            return Err(RuntimeError::new(Kind::InvalidInput,
                "Win16 hmemcpy received a negative byte count"));
        }
        if count == 0 {
            return Ok(());
        }

        let source = self.selectors.pointer_from_far(source).map_err(crate::runtime_error)?;
        let destination = self.selectors.pointer_from_far(destination).map_err(crate::runtime_error)?;
        self.preflight_text_write(memory, destination, count as usize)?;
        let bytes = self.read_text_bytes(memory, source, count as usize)?;
        self.write_text_bytes(memory, destination, &bytes)
    }
}

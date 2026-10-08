//! Guest output marshalling for Windows-managed registered names.

use super::Win16State;
use guest_core::memory::Memory;
use crate::{DiagnosticKind as Kind, RuntimeError, RuntimeHost};

impl Win16State {
    pub(super) fn clipboard_format_name(&self, format: u16, output: u32, count: i16,
        memory: &mut Memory, host: &mut impl RuntimeHost) -> Result<u16, RuntimeError> {
        if count <= 0 || output == 0 { return Ok(0); }
        let pointer = self.selectors.pointer_from_far(output).map_err(crate::runtime_error)?;
        let capacity = count as usize;
        self.preflight_text_write(memory, pointer, capacity)?;
        let buffer = self.read_text_bytes(memory, pointer, capacity)?;
        let (buffer, copied) = host.win16_clipboard_format_name(format, buffer)?;
        if buffer.len() != capacity || usize::from(copied) > capacity {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "native clipboard-format result exceeds its guest output buffer"));
        }
        self.write_text_bytes(memory, pointer, &buffer)?;
        Ok(copied)
    }
}

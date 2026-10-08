//! Win16 KEYBOARD driver requests and guest string writeback.

use guest_core::memory::Memory;

use super::Win16State;
use crate::{DiagnosticKind as Kind, RuntimeError, RuntimeHost};

impl Win16State {
    pub(super) fn oem_to_ansi(
        &self,
        source: &[u8],
        destination: u32,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u16, RuntimeError> {
        let mut ansi = host.win16_oem_to_ansi(source)?;
        ansi.try_reserve(1).map_err(|_| RuntimeError::new(Kind::ResourceExhausted,
            "Win16 OEM-to-ANSI result could not reserve a terminator"))?;
        ansi.push(0);
        let pointer = self.selectors.pointer_from_far(destination)
            .map_err(crate::runtime_error)?;
        // SelectorTable validates the full range before committing the write.
        self.selectors.write(memory, pointer, &ansi).map_err(crate::runtime_error)?;
        Ok(u16::MAX)
    }
}

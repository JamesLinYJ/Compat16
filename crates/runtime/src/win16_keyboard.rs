//! Win16 KEYBOARD driver requests and guest string writeback.

use guest_core::memory::Memory;

use super::Win16State;
use crate::{DiagnosticKind as Kind, RuntimeError, RuntimeHost, Win16HostKeyboardCall,
    Win16HostKeyboardResult};

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
        // The same huge-pointer contract applies to the destination. Prepare
        // every selector in the owned allocation first, so a span that is not
        // fully writable leaves the guest bytes unchanged.
        self.write_text_bytes(memory, pointer, &ansi)?;
        Ok(u16::MAX)
    }

    pub(super) fn ansi_to_oem(
        &self,
        source: Vec<u8>,
        destination: u32,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u16, RuntimeError> {
        let Win16HostKeyboardResult::Converted(mut oem) = host.win16_keyboard(
            Win16HostKeyboardCall::AnsiToOem { source },
        )? else {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "host returned the wrong result for Win16 AnsiToOem"));
        };
        oem.try_reserve(1).map_err(|_| RuntimeError::new(Kind::ResourceExhausted,
            "Win16 ANSI-to-OEM result could not reserve a terminator"))?;
        oem.push(0);
        let pointer = self.selectors.pointer_from_far(destination)
            .map_err(crate::runtime_error)?;
        // Windows 3.1 AnsiToOem takes huge pointers. Prepare every selector
        // in the owned allocation first, so a span that is not fully writable
        // leaves the guest bytes unchanged.
        self.write_text_bytes(memory, pointer, &oem)?;
        Ok(u16::MAX)
    }
}

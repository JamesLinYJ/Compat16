//! Protected-mode routing for DOS INT 21h services with scalar contracts.
//!
//! Parameter classification follows the existing DOS register semantics.
//! DOS far pointers require the caller's address-space
//! route: a protected selector is not a real-mode segment, and host pointers
//! are never converted back into guest pointers.

use crate::{DosAction, DosError, DosErrorCode, DosHost, DosHostError};
use guest_core::{GuestMemory, Registers};

use super::DosKernel;

impl DosKernel {
    /// Route INT 21h functions whose operands and results are register-only.
    ///
    /// `memory` is reserved for the ordinary DOS kernel metadata preflight and
    /// refresh performed by `interrupt`; it does not back the protected
    /// caller's selectors or translate DS/ES into DOS addresses. `number` is
    /// the interrupt vector (21h); the DOS function number remains in AH.
    pub fn interrupt_scalar(
        &mut self,
        number: u8,
        regs: &mut Registers,
        memory: &mut impl GuestMemory,
        host: &mut impl DosHost,
    ) -> Result<Option<DosAction>, DosError> {
        if number != 0x21 {
            return Ok(None);
        }
        if regs.ah() == 0x00 {
            // Windows 3.1 SDK Vol.1 section 20.2.1, printed p.403, excludes
            // AH=00 from protected-mode DOS. It does not define result bits;
            // use our ordinary unsupported-DOS result, not real-mode task
            // termination or handle cleanup. This is an explicit policy,
            // not a claim about an observed original Windows return value.
            self.prepare_external_int21(memory)?;
            Self::failure(regs, DosHostError::new(DosErrorCode::InvalidFunction));
            self.finish_external_int21(memory, host)?;
            return Ok(Some(DosAction::Continue));
        }

        // Only established scalar DOS contracts enter the real-mode kernel
        // lifecycle. Buffer, path, DTA, vector, PSP, MCB, and file-handle
        // services stay on the caller's address-space or ownership route.
        let scalar = match regs.ah() {
            0x01 | 0x02 | 0x06 | 0x07 | 0x08 | 0x0b | 0x0e | 0x19
            | 0x2a | 0x2c | 0x30 | 0x33 | 0x36 | 0x4c | 0x4d => true,
            // AH=0Ch's AL=0Ah subfunction consumes DS:DX; the other listed
            // subfunctions are console operations entirely in registers.
            0x0c => matches!(regs.al(), 0x01 | 0x06 | 0x07 | 0x08),
            _ => false,
        };
        if !scalar {
            return Ok(None);
        }

        // Reuse the full DOS lifecycle so system-table/MCB preflight, SFT
        // refresh, error flags, 16-bit register results, and exit handling
        // stay with their owner.
        self.interrupt(number, regs, memory, host).map(Some)
    }

    /// Preflight shared DOS metadata before an external protected-mode INT 21h
    /// adapter updates a DOS state item such as an interrupt vector.
    ///
    /// Pair this with `finish_external_int21` after the adapter succeeds.
    /// The memory is the DOS guest's real-mode metadata storage; protected-mode
    /// selectors in caller registers must not be passed to `real_address`.
    pub fn prepare_external_int21(
        &mut self,
        memory: &mut impl GuestMemory,
    ) -> Result<(), DosError> {
        self.validate_system_tables(memory)?;
        if self.system_tables.is_some() {
            let _ = self.mcb_chain(memory)?;
        }
        Ok(())
    }

    /// Refresh the shared DOS system tables after an external protected-mode
    /// INT 21h adapter has successfully updated DOS state.
    pub fn finish_external_int21(
        &mut self,
        memory: &mut impl GuestMemory,
        host: &mut impl DosHost,
    ) -> Result<(), DosError> {
        self.refresh_system_tables(memory, host)
    }
}

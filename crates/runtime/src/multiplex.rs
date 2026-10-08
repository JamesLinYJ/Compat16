//! Runtime-connected INT 2Fh multiplex providers.
//!
//! An unclaimed request reaches the end of the installed DOS multiplex head;
//! the caller should complete the saved interrupt frame with IRET rather than
//! falling through to an unrelated BIOS service.

use guest_core::Registers;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MultiplexOutcome {
    Handled,
    Unclaimed,
    MissingDosService,
}

/// Dispatch an INT 2Fh request to providers connected to this runtime.
///
/// XMS and the configured Windows compatibility-version profile are installed
/// providers. Unimplemented DPMI, VxD, and other Windows services remain
/// unclaimed.
pub(crate) fn dispatch(regs: &mut Registers) -> MultiplexOutcome {
    // DOS itself owns AH=12h. Its internal services cannot be mistaken for
    // an absent optional provider; missing implementations remain explicit.
    if regs.ah() == 0x12 { return MultiplexOutcome::MissingDosService; }
    // MS DOS 4 MS_CODE.ASM 486-503: when SHARE, network redirector or NLSFUNC
    // is absent, non-installation calls return invalid-function with carry.
    if matches!(regs.ah(), 0x10 | 0x11 | 0x14) && regs.al() != 0 {
        regs.set_ax(dos_kernel::DosErrorCode::InvalidFunction as u16);
        regs.set_carry(true);
        return MultiplexOutcome::Handled;
    }
    if win16_abi::handle_int2f_version_query(
        regs,
        &win16_abi::WINDOWS_COMPATIBILITY_PROFILE,
    ) {
        return MultiplexOutcome::Handled;
    }
    if xms::handle_int2f(regs, crate::XMS_ENTRY) {
        MultiplexOutcome::Handled
    } else {
        MultiplexOutcome::Unclaimed
    }
}

#[cfg(test)]
#[path = "multiplex_tests.rs"]
mod tests;

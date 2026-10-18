//! DOS INT 21h/AH=59h: retain the error, rather than interpreting the incoming
//! FLAGS from a later call as an indication that the earlier call failed.
//!
//! Register layout: MS-DOS 4 GETSET.ASM ($GetExtendedError). Classification:
//! MS_TABLE.ASM ERR_TABLE_21/24 and INC/ERROR.INC, Microsoft MIT licensed.
//! https://github.com/microsoft/MS-DOS/tree/2d04cacc5322951f187bb17e017c12920ac8ebe2/v4.0/src
//! See LICENSES/Microsoft-MS-DOS-MIT.txt.

use super::DosKernel;
use crate::DosAction;
use guest_core::Registers;
use std::{cell::Cell, rc::Rc};

#[derive(Clone, Copy, Debug, Default)]
struct ExtendedError {
    code: u16,
    class: u8,
    action: u8,
    locus: u8,
}

/// Like the DOS error variables, shared by an EXEC tree rather than by PSP.
#[derive(Clone, Debug, Default)]
pub(super) struct ExtendedErrorState(Rc<Cell<ExtendedError>>);

impl DosKernel {
    /// Publish an actual DOS failure from the kernel or a protected adapter.
    /// The raw DOS code is retained even when its classification is unknown.
    /// Call this at the failure site; successful calls can leave CF unchanged.
    pub fn complete_service_failure(&mut self, regs: &mut Registers, code: u16) {
        let (class, action, locus) = match code {
            1 => (7, 4, 1),
            2 | 3 | 15 | 18 => (8, 3, 2),
            4 | 39 => (1, 4, 1),
            5 => (3, 3, 1),
            6 | 12 => (7, 4, 1),
            7 => (7, 5, 5),
            8 => (1, 4, 5),
            9 | 10 => (7, 4, 5),
            11 => (9, 3, 1),
            13 => (9, 4, 1),
            16 => (3, 3, 2),
            17 => (13, 3, 2),
            19 => (11, 7, 2),
            21 => (5, 7, 1),
            32 | 33 => (10, 2, 2),
            80 => (12, 3, 2),
            _ => (13, 4, 1),
        };
        // Table entries with call-specific locus use DOS's unknown default.
        // No critical-error/device frame is available from these adapters;
        // do not invent a disk/device identity or a guest error-info pointer.
        self.extended_error.0.set(ExtendedError {
            code,
            class,
            action,
            locus,
        });
        regs.set_ax(code);
        regs.set_carry(true);
    }

    pub(super) fn get_extended_error(&self, regs: &mut Registers) -> DosAction {
        let error = self.extended_error.0.get();
        regs.set_ax(error.code);
        regs.set_bx(u16::from_be_bytes([error.class, error.action]));
        regs.set_ch(error.locus);
        // The supported errors have no critical-error info block. NULL is
        // also a valid protected-mode result and requires no selector bridge.
        regs.es = 0;
        regs.set_di(0);
        regs.set_carry(false);
        DosAction::Continue
    }
}

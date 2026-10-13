//! INT 21h/AH=59h extended error, classified from the MS-DOS 4.0 tables.
//!
//! `ERR_TABLE_21` and `ERR_TABLE_24` in MS-DOS 4.0 `MS_TABLE.ASM` map an error
//! code to class, suggested action, and locus. A locus of `0FFh` means the
//! failing call was supposed to supply one. This kernel has no separate
//! per-call locus seed, so an unspecified locus is reported as unknown (`01h`)
//! instead of retaining whatever locus a previous call stored.

use guest_core::Registers;

use crate::{DosAction, DosErrorCode, DosHostError};

use super::DosKernel;

const CLASS_OUT_OF_RESOURCE: u8 = 0x01;
const CLASS_AUTHORIZATION: u8 = 0x03;
const CLASS_HARDWARE: u8 = 0x05;
const CLASS_APPLICATION: u8 = 0x07;
const CLASS_NOT_FOUND: u8 = 0x08;
const CLASS_BAD_FORMAT: u8 = 0x09;
const CLASS_LOCKED: u8 = 0x0a;
const CLASS_MEDIA: u8 = 0x0b;
const CLASS_ALREADY_EXISTS: u8 = 0x0c;
const CLASS_UNKNOWN: u8 = 0x0d;

const ACTION_DELAYED_RETRY: u8 = 0x02;
const ACTION_USER: u8 = 0x03;
const ACTION_ABORT: u8 = 0x04;
const ACTION_PANIC: u8 = 0x05;
const ACTION_INTERVENTION: u8 = 0x07;

const LOCUS_UNKNOWN: u8 = 0x01;
const LOCUS_DISK: u8 = 0x02;
const LOCUS_MEMORY: u8 = 0x05;
/// MS-DOS table sentinel: the call should already have chosen a locus.
const LOCUS_CALL_SPECIFIC: u8 = 0xff;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ExtendedError {
    pub(super) code: u16,
    pub(super) class: u8,
    pub(super) action: u8,
    pub(super) locus: u8,
}

impl ExtendedError {
    pub(super) const NONE: Self = Self {
        code: 0,
        class: 0,
        action: 0,
        locus: 0,
    };

    pub(super) fn classify(code: u16) -> Self {
        let (class, action, locus) = match code {
            1 => (CLASS_APPLICATION, ACTION_ABORT, LOCUS_CALL_SPECIFIC),
            2 | 3 | 15 | 18 => (CLASS_NOT_FOUND, ACTION_USER, LOCUS_DISK),
            4 => (CLASS_OUT_OF_RESOURCE, ACTION_ABORT, LOCUS_UNKNOWN),
            5 => (CLASS_AUTHORIZATION, ACTION_USER, LOCUS_CALL_SPECIFIC),
            6 | 12 => (CLASS_APPLICATION, ACTION_ABORT, LOCUS_UNKNOWN),
            7 => (CLASS_APPLICATION, ACTION_PANIC, LOCUS_MEMORY),
            8 => (CLASS_OUT_OF_RESOURCE, ACTION_ABORT, LOCUS_MEMORY),
            9 | 10 => (CLASS_APPLICATION, ACTION_ABORT, LOCUS_MEMORY),
            11 => (CLASS_BAD_FORMAT, ACTION_USER, LOCUS_UNKNOWN),
            13 => (CLASS_BAD_FORMAT, ACTION_ABORT, LOCUS_UNKNOWN),
            16 => (CLASS_AUTHORIZATION, ACTION_USER, LOCUS_DISK),
            17 => (CLASS_UNKNOWN, ACTION_USER, LOCUS_DISK),
            19 => (CLASS_MEDIA, ACTION_INTERVENTION, LOCUS_DISK),
            21 => (CLASS_HARDWARE, ACTION_INTERVENTION, LOCUS_CALL_SPECIFIC),
            31 => (CLASS_UNKNOWN, ACTION_ABORT, LOCUS_CALL_SPECIFIC),
            32 | 33 => (CLASS_LOCKED, ACTION_DELAYED_RETRY, LOCUS_DISK),
            39 => (CLASS_OUT_OF_RESOURCE, ACTION_ABORT, LOCUS_CALL_SPECIFIC),
            80 => (CLASS_ALREADY_EXISTS, ACTION_USER, LOCUS_DISK),
            // INT 24 catch-all: unknown class, panic, locus left unspecified.
            _ => (CLASS_UNKNOWN, ACTION_PANIC, LOCUS_CALL_SPECIFIC),
        };
        Self {
            code,
            class,
            action,
            locus: if locus == LOCUS_CALL_SPECIFIC {
                LOCUS_UNKNOWN
            } else {
                locus
            },
        }
    }
}

impl DosKernel {
    pub(super) fn prepare_extended_error(&self) {
        self.extended_error_touched.set(false);
        self.preserve_extended_error.set(false);
    }

    pub(super) fn finish_extended_error(&self) {
        if self.preserve_extended_error.get() {
            self.preserve_extended_error.set(false);
            self.extended_error_touched.set(false);
            return;
        }
        if !self.extended_error_touched.get() {
            self.extended_error.set(ExtendedError::NONE);
        }
        self.extended_error_touched.set(false);
    }

    pub(super) fn success(&self, regs: &mut Registers) {
        self.extended_error.set(ExtendedError::NONE);
        self.extended_error_touched.set(true);
        self.preserve_extended_error.set(false);
        regs.set_carry(false);
    }

    pub(super) fn failure(&self, regs: &mut Registers, error: DosHostError) {
        self.record_extended_error(error.code as u16);
        regs.set_ax(error.code as u16);
        regs.set_carry(true);
    }

    /// AH=68h/AH=6Ah may show a different code in AX than the one AH=59h keeps.
    pub(super) fn fail_with_extended_cause(
        &self,
        regs: &mut Registers,
        actual: DosErrorCode,
        visible: DosErrorCode,
    ) {
        self.record_extended_error(actual as u16);
        regs.set_ax(visible as u16);
        regs.set_carry(true);
    }

    /// Guest-visible failure decided outside `int21`, such as a rejected EXEC.
    pub fn complete_service_failure(&self, regs: &mut Registers, code: DosErrorCode) {
        self.failure(regs, DosHostError::new(code));
    }

    fn record_extended_error(&self, code: u16) {
        self.extended_error.set(ExtendedError::classify(code));
        self.extended_error_touched.set(true);
        self.preserve_extended_error.set(false);
    }

    /// INT 21h/AH=59h/BX=0000h. The query reports the stored failure and does
    /// not clear it. A nonzero BX is an unsupported subfunction and replaces
    /// the stored failure with invalid function.
    ///
    /// ES:DI is left unchanged. This core does not generate the media-change
    /// errors whose extra pointer would occupy that pair. CL, DX, SI, BP, and
    /// DS are also preserved; historical DOS destroyed them.
    pub(super) fn get_extended_error(&self, regs: &mut Registers) -> DosAction {
        if regs.bx() != 0 {
            self.failure(regs, DosHostError::new(DosErrorCode::InvalidFunction));
            return DosAction::Continue;
        }
        let error = self.extended_error.get();
        regs.set_ax(error.code);
        regs.set_bh(error.class);
        regs.set_bl(error.action);
        regs.set_ch(error.locus);
        regs.set_carry(false);
        self.preserve_extended_error.set(true);
        self.extended_error_touched.set(true);
        DosAction::Continue
    }
}

#[cfg(test)]
mod tests {
    use super::ExtendedError;

    #[test]
    fn classified_codes_follow_the_dos4_tables() {
        let rows = [
            (1, 0x07, 0x04, 0x01),
            (2, 0x08, 0x03, 0x02),
            (3, 0x08, 0x03, 0x02),
            (4, 0x01, 0x04, 0x01),
            (5, 0x03, 0x03, 0x01),
            (6, 0x07, 0x04, 0x01),
            (7, 0x07, 0x05, 0x05),
            (8, 0x01, 0x04, 0x05),
            (9, 0x07, 0x04, 0x05),
            (10, 0x07, 0x04, 0x05),
            (11, 0x09, 0x03, 0x01),
            (12, 0x07, 0x04, 0x01),
            (13, 0x09, 0x04, 0x01),
            (15, 0x08, 0x03, 0x02),
            (16, 0x03, 0x03, 0x02),
            (17, 0x0d, 0x03, 0x02),
            (18, 0x08, 0x03, 0x02),
            (19, 0x0b, 0x07, 0x02),
            (21, 0x05, 0x07, 0x01),
            (31, 0x0d, 0x04, 0x01),
            (32, 0x0a, 0x02, 0x02),
            (33, 0x0a, 0x02, 0x02),
            (39, 0x01, 0x04, 0x01),
            (80, 0x0c, 0x03, 0x02),
            (99, 0x0d, 0x05, 0x01),
        ];
        for (code, class, action, locus) in rows {
            assert_eq!(
                ExtendedError::classify(code),
                ExtendedError {
                    code,
                    class,
                    action,
                    locus
                },
                "code {code}",
            );
        }
    }
}

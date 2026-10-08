//! BIOS INT 17h behavior when the VDM has no mapped parallel printer.
//!
//! The IBM PC/AT BIOS Interface Technical Reference (April 1987, INT 17h,
//! pp. 2-111–2-112) defines status bit 7 as not-busy, bit 4 as selected,
//! bit 3 as I/O error, and bit 0 as timeout. With no configured LPT device,
//! the runtime reports bit 3 and bit 0, and leaves ready/selected/paper signals
//! clear. This is an explicit absent-device result; it does not claim a host
//! printer is attached and it does not emit or spool characters.

use guest_core::Registers;

const PRINTER_TIMEOUT: u8 = 1 << 0;
const PRINTER_IO_ERROR: u8 = 1 << 3;
const ABSENT_PRINTER_STATUS: u8 = PRINTER_TIMEOUT | PRINTER_IO_ERROR;

/// Dispatch the supported classic printer functions for an absent LPT device.
///
/// AH=00h writes a character, AH=01h initializes the port, and AH=02h reads
/// status. All three return the same timeout/I/O-error status because this
/// runtime has no configured DOS printer. Reserved function numbers are
/// ignored with the input register frame intact instead of terminating the
/// guest.
pub(crate) fn dispatch(regs: &mut Registers) {
    match regs.ah() {
        0x00..=0x02 => regs.set_ah(ABSENT_PRINTER_STATUS),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::{dispatch, ABSENT_PRINTER_STATUS};
    use guest_core::Registers;

    fn input_regs(function: u8) -> Registers {
        Registers {
            eax: 0x1234_0000 | (u32::from(function) << 8) | 0x005a,
            ebx: 0x2345_6789,
            ecx: 0x3456_789a,
            edx: 0x4567_89ab,
            esi: 0x5678_9abc,
            edi: 0x6789_abcd,
            eflags: 0x0000_0fd7,
            cs: 0x1111,
            ds: 0x2222,
            es: 0x3333,
            ss: 0x4444,
            ..Registers::default()
        }
    }

    #[test]
    fn absent_printer_functions_report_timeout_and_io_error_without_faking_ready() {
        for function in 0..=2 {
            let mut regs = input_regs(function);
            let original = regs.clone();
            dispatch(&mut regs);

            assert_eq!(regs.ah(), ABSENT_PRINTER_STATUS, "AH={function:02X}");
            assert_eq!(regs.al(), original.al(), "AH={function:02X}");
            assert_eq!(regs.ebx, original.ebx);
            assert_eq!(regs.ecx, original.ecx);
            assert_eq!(regs.edx, original.edx);
            assert_eq!(regs.eflags, original.eflags);
            assert_eq!(regs.cs, original.cs);
            assert_eq!(regs.ds, original.ds);
            assert_eq!(regs.es, original.es);
            assert_eq!(regs.ss, original.ss);
            assert_eq!(regs.ah() & 0x80, 0); // Not ready/not busy is not claimed.
            assert_eq!(regs.ah() & 0x10, 0); // No attached printer is claimed selected.
        }
    }

    #[test]
    fn reserved_printer_functions_are_ignored_without_register_changes() {
        for function in [0x03, 0x7f, 0xff] {
            let mut regs = input_regs(function);
            let original = regs.clone();
            dispatch(&mut regs);
            assert_eq!(regs, original, "AH={function:02X}");
        }
    }
}

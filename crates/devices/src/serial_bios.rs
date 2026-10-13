//! INT 14h serial services for a machine with no COM port.
//!
//! AH=00h initializes, AH=01h transmits, AH=02h receives, and AH=03h reads
//! status. With no UART, line status bit 7 reports a timeout and the modem
//! status is zero. Other function numbers leave the register frame unchanged.

use guest_core::Registers;

const LINE_TIMEOUT: u8 = 0x80;

pub(crate) fn dispatch(regs: &mut Registers) {
    match regs.ah() {
        0x00..=0x03 => {
            regs.set_ah(LINE_TIMEOUT);
            regs.set_al(0);
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::dispatch;
    use guest_core::Registers;

    #[test]
    fn absent_serial_port_reports_timeout_and_clears_modem_status() {
        for function in 0..=3 {
            let mut regs = Registers::default();
            regs.set_ah(function);
            regs.set_al(0x5a);
            regs.set_dx(0);
            dispatch(&mut regs);
            assert_eq!(regs.ah(), 0x80, "AH={function:02X}");
            assert_eq!(regs.al(), 0, "AH={function:02X}");
        }
    }

    #[test]
    fn unsupported_serial_function_preserves_the_frame() {
        let mut regs = Registers::default();
        regs.set_ax(0x04ff);
        regs.set_dx(1);
        let original = regs.clone();
        dispatch(&mut regs);
        assert_eq!(regs, original);
    }
}

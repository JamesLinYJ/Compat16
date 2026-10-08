//! Minimal INT 2Ah behavior when no DOS network provider is installed.

use dos_kernel::DosAction;
use guest_core::Registers;

/// Handle the one network-vector query for which this runtime has a truthful
/// answer. Microsoft Networks uses AH=00h to query installation, returning
/// AH=00h when absent and nonzero when installed. No redirector is configured
/// here, so preserve the input frame: the query's AH remains zero. A historical
/// DOS INT 2Ah implementation uses the same no-op behavior for AH=00h.
///
/// Other INT 2Ah functions require a network/server provider or have separate
/// semantics, so they remain unclaimed for the normal interrupt chain.
pub(crate) fn int2a(regs: &mut Registers) -> DosAction {
    match regs.ah() {
        0x00 => DosAction::Continue,
        _ => DosAction::Unhandled,
    }
}

#[cfg(test)]
mod tests {
    use super::int2a;
    use dos_kernel::DosAction;
    use guest_core::Registers;

    #[test]
    fn installation_check_reports_absent_network_without_changing_the_frame() {
        let mut regs = Registers {
            eax: 0x1234_005a,
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
        };
        let input = regs.clone();

        assert_eq!(int2a(&mut regs), DosAction::Continue);
        assert_eq!(regs, input);
        assert_eq!(regs.ah(), 0);
    }

    #[test]
    fn provider_specific_network_calls_are_unclaimed() {
        for ah in [0x01u8, 0x03, 0x04, 0x05, 0x80, 0x81, 0x82, 0x84] {
            let mut regs = Registers::default();
            regs.set_ax(u16::from(ah) << 8 | 0x01);
            regs.ebx = 0x1234_5678;
            regs.eflags = 0x0000_0fd7;
            let input = regs.clone();

            assert_eq!(int2a(&mut regs), DosAction::Unhandled, "AH={ah:02X}");
            assert_eq!(regs, input, "AH={ah:02X}");
        }
    }
}

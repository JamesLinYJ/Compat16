//! Actual protected selector ranges for AH=29h, without native file I/O.
use super::*;

fn parse(
    readable: u32,
    writable: u32,
    read_only_output: bool,
) -> (Registers, Result<DosAction, DosError>, [u8; 32]) {
    let (mut runtime, mut host) = fixture();
    let parent = runtime.dos.psp_segment();
    let input_base = real_address(parent, 0x800);
    let output_base = real_address(parent, 0x1000);
    runtime.memory.write(input_base, b"ab.txt\0").unwrap();
    runtime.memory.write(output_base, &[0xa5; 32]).unwrap();
    let mut selectors = SelectorTable::new().unwrap();
    let input = selectors
        .alloc_block(
            input_base,
            readable,
            AccessRights::read_only(),
            &runtime.memory,
        )
        .unwrap();
    let output = selectors
        .alloc_block(
            output_base,
            writable,
            if read_only_output {
                AccessRights::read_only()
            } else {
                AccessRights::read_write()
            },
            &runtime.memory,
        )
        .unwrap();
    let mut addresses = Win16DosCallerAddresses::default();
    let mut regs = Registers {
        eax: 0x1234_2900,
        esi: 0x2345_0000,
        edi: 0x3456_0000,
        ds: input.raw().0,
        es: output.raw().0,
        eflags: 0x246,
        ..Default::default()
    };
    let before = regs.clone();
    let result = {
        let mut memory = Win16DosAddressSpace {
            selectors: &mut selectors,
            addresses: &mut addresses,
            memory: runtime.memory.bus(),
            caller: DosCallerId::new(1).unwrap(),
        };
        runtime
            .dos
            .interrupt_with_address_space(0x21, &mut regs, &mut memory, &mut host)
    };
    if result.is_err() {
        assert_eq!(regs, before);
    }
    assert_eq!((host.opens, host.closes, host.open), (0, 0, false));
    let mut bytes = [0; 32];
    runtime.memory.read(output_base, &mut bytes).unwrap();
    (regs, result, bytes)
}

#[test]
fn fcb_parse_protected_uses_selectors_and_exact_sixteen_byte_output() {
    let (regs, result, bytes) = parse(7, 16, false);
    assert_eq!(result.unwrap(), DosAction::Continue);
    assert_eq!(
        (regs.al(), regs.esi, regs.edi),
        (0, 0x2345_0006, 0x3456_0000)
    );
    assert_eq!(&bytes[..12], b"\0AB      TXT");
    assert_eq!(&bytes[12..16], &[0; 4]);
    assert_eq!(&bytes[16..], &[0xa5; 16]);
}

#[test]
fn fcb_parse_protected_short_or_read_only_ranges_do_not_publish_output() {
    for (readable, writable, read_only) in [(6, 16, false), (7, 15, false), (7, 16, true)] {
        let (_, result, bytes) = parse(readable, writable, read_only);
        assert!(matches!(
            result,
            Err(DosError::CallerAddressSpace {
                kind: DosCallerAddressSpaceFailureKind::InvalidPointer,
                ..
            })
        ));
        assert_eq!(bytes, [0xa5; 32]);
    }
}

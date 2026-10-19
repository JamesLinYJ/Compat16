use super::*;

#[test]
fn canonical_name_protected_uses_readonly_input_and_checked_output_selectors() {
    for (length, read_only) in [(128, false), (127, false), (128, true)] {
        let (mut runtime, mut host) = fixture();
        let base = real_address(runtime.dos.psp_segment(), 0x1000);
        runtime.memory.write(base, b"probe.txt\0").unwrap();
        runtime
            .memory
            .write(PhysAddr(base.0 + 0x100), &[0xa5; 130])
            .unwrap();
        let mut selectors = SelectorTable::new().unwrap();
        let input = selectors
            .alloc_block(base, 10, AccessRights::read_only(), &runtime.memory)
            .unwrap();
        let output = selectors
            .alloc_block(
                PhysAddr(base.0 + 0x100),
                length,
                if read_only {
                    AccessRights::read_only()
                } else {
                    AccessRights::read_write()
                },
                &runtime.memory,
            )
            .unwrap();
        let mut addresses = Win16DosCallerAddresses::default();
        let mut memory = Win16DosAddressSpace {
            selectors: &mut selectors,
            addresses: &mut addresses,
            memory: runtime.memory.bus(),
            caller: DosCallerId::new(1).unwrap(),
        };
        let mut regs = Registers {
            eax: 0x1234_6000,
            ds: input.raw().0,
            es: output.raw().0,
            ebx: 0x2345_1234,
            ecx: 0x3456_2345,
            esi: 0xabcd_0000,
            edi: 0xbcde_0000,
            eflags: 0xad57,
            ..Default::default()
        };
        let before = regs.clone();
        let result =
            runtime
                .dos
                .interrupt_with_address_space(0x21, &mut regs, &mut memory, &mut host);
        let mut bytes = [0; 130];
        runtime
            .memory
            .read(PhysAddr(base.0 + 0x100), &mut bytes)
            .unwrap();
        if length == 128 && !read_only {
            result.unwrap();
            let mut expected = before;
            expected.set_ax(0x5c);
            expected.set_carry(false);
            assert_eq!(regs, expected);
            assert_eq!(&bytes[..18], b"C:\\WORK\\PROBE.TXT\0");
            assert!(bytes[18..].iter().all(|byte| *byte == 0xa5));
        } else {
            assert!(result.is_err());
            assert_eq!(regs, before);
            assert_eq!(bytes, [0xa5; 130]);
        }
    }
}

#[test]
fn canonical_name_protected_allows_overlapping_input_and_output() {
    let (mut runtime, mut host) = fixture();
    let base = real_address(runtime.dos.psp_segment(), 0x1000);
    runtime.memory.write(base, &[0xa5; 128]).unwrap();
    runtime.memory.write(base, b"probe.txt\0").unwrap();
    let mut selectors = SelectorTable::new().unwrap();
    let selector = selectors
        .alloc_block(base, 128, AccessRights::read_write(), &runtime.memory)
        .unwrap();
    let mut addresses = Win16DosCallerAddresses::default();
    let mut memory = Win16DosAddressSpace {
        selectors: &mut selectors,
        addresses: &mut addresses,
        memory: runtime.memory.bus(),
        caller: DosCallerId::new(1).unwrap(),
    };
    let mut regs = Registers {
        eax: 0x6000,
        ds: selector.raw().0,
        es: selector.raw().0,
        ..Default::default()
    };
    runtime
        .dos
        .interrupt_with_address_space(0x21, &mut regs, &mut memory, &mut host)
        .unwrap();
    assert!(!regs.carry());
    let mut bytes = [0; 18];
    runtime.memory.read(base, &mut bytes).unwrap();
    assert_eq!(&bytes, b"C:\\WORK\\PROBE.TXT\0");
}

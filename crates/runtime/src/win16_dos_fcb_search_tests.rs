//! FCB searches use checked live selectors and the retained DTA generation.
use super::*;

struct Search {
    runtime: Runtime,
    host: ExecHost,
    selectors: SelectorTable,
    addresses: Win16DosCallerAddresses,
    fcb: u16,
    dta: u16,
    base: PhysAddr,
}

impl Search {
    fn new(
        extended: bool,
        input_len: u32,
        output_len: u32,
        input_read_only: bool,
        output_read_only: bool,
    ) -> Self {
        let (mut runtime, mut host) = fixture();
        host.search_entries = [b"A.TXT".as_slice(), b"B.TXT"]
            .into_iter()
            .map(|name| DosDirectoryEntry {
                short_name: name.to_vec(),
                attributes: 0x20,
                write_time: 0x7bcd,
                write_date: 0x56a7,
                size: 18,
            })
            .collect();
        let base = real_address(runtime.dos.psp_segment(), 0x1000);
        let mut bytes = [0; 29];
        let skip = if extended {
            bytes[0] = 0xff;
            7
        } else {
            0
        };
        bytes[skip + 1..skip + 12].copy_from_slice(b"?       TXT");
        runtime.memory.write(base, &bytes).unwrap();
        runtime
            .memory
            .write(PhysAddr(base.0 + 0x100), &[0xa5; 80])
            .unwrap();
        let mut selectors = SelectorTable::new().unwrap();
        let input = selectors
            .alloc_block(
                base,
                input_len,
                if input_read_only {
                    AccessRights::read_only()
                } else {
                    AccessRights::read_write()
                },
                &runtime.memory,
            )
            .unwrap();
        let output = selectors
            .alloc_block(
                PhysAddr(base.0 + 0x100),
                output_len,
                if output_read_only {
                    AccessRights::read_only()
                } else {
                    AccessRights::read_write()
                },
                &runtime.memory,
            )
            .unwrap();
        let mut test = Self {
            runtime,
            host,
            selectors,
            addresses: Win16DosCallerAddresses::default(),
            fcb: input.raw().0,
            dta: output.raw().0,
            base,
        };
        test.set_dta(1, test.dta);
        test
    }

    fn dispatch(&mut self, caller: u64, regs: &mut Registers) -> Result<DosAction, DosError> {
        let mut memory = Win16DosAddressSpace {
            selectors: &mut self.selectors,
            addresses: &mut self.addresses,
            memory: self.runtime.memory.bus(),
            caller: DosCallerId::new(caller).unwrap(),
        };
        self.runtime
            .dos
            .interrupt_with_address_space(0x21, regs, &mut memory, &mut self.host)
    }

    fn set_dta(&mut self, caller: u64, selector: u16) {
        let mut regs = Registers {
            eax: 0x1a00,
            ds: selector,
            ..Default::default()
        };
        self.dispatch(caller, &mut regs).unwrap();
    }

    fn call(&mut self, caller: u64, ah: u8) -> (Registers, Result<DosAction, DosError>) {
        let mut regs = Registers {
            eax: 0x1234_0007 | (u32::from(ah) << 8),
            ebx: 0x2345_1234,
            ecx: 0x3456_2345,
            edx: 0x4567_0000,
            esi: 0x5678_3456,
            edi: 0x6789_4567,
            ds: self.fcb,
            es: 0xffff,
            eflags: 0xad57,
            ..Default::default()
        };
        let before = regs.clone();
        let result = self.dispatch(caller, &mut regs);
        let mut expected = before;
        if result.is_ok() {
            expected.set_al(regs.al());
        }
        assert_eq!(regs, expected);
        (regs, result)
    }
}

#[test]
fn fcb_search_protected_writes_exact_normal_and_extended_records() {
    for extended in [false, true] {
        let skip = if extended { 7 } else { 0 };
        let mut test = Search::new(extended, 22 + skip, 33 + skip, false, false);
        let (regs, result) = test.call(1, 0x11);
        result.unwrap();
        assert_eq!(regs.al(), 0);
        let mut bytes = [0; 80];
        test.runtime
            .memory
            .read(PhysAddr(test.base.0 + 0x100), &mut bytes)
            .unwrap();
        assert_eq!(
            &bytes[skip as usize..skip as usize + 13],
            b"\x03A       TXT\x20"
        );
        assert_eq!(
            &bytes[skip as usize + 23..skip as usize + 27],
            &[0xcd, 0x7b, 0xa7, 0x56]
        );
        assert!(bytes[33 + skip as usize..].iter().all(|&byte| byte == 0xa5));
        assert_eq!((test.host.search_opens, test.host.search_closes), (1, 1));
    }
}

#[test]
fn fcb_search_protected_bad_ranges_precede_host_and_output_changes() {
    for (extended, input, output, read_input, read_output) in [
        (false, 21, 33, false, false),
        (false, 22, 32, false, false),
        (false, 22, 33, true, false),
        (false, 22, 33, false, true),
        (true, 29, 39, false, false),
    ] {
        let mut test = Search::new(extended, input, output, read_input, read_output);
        let (_, result) = test.call(1, 0x11);
        assert!(matches!(
            result,
            Err(DosError::CallerAddressSpace {
                kind: DosCallerAddressSpaceFailureKind::InvalidPointer,
                ..
            })
        ));
        assert_eq!((test.host.search_opens, test.host.search_closes), (0, 0));
        let mut bytes = [0; 80];
        test.runtime
            .memory
            .read(PhysAddr(test.base.0 + 0x100), &mut bytes)
            .unwrap();
        assert_eq!(bytes, [0xa5; 80]);
    }
}

#[test]
fn fcb_search_protected_copy_and_dta_move_survive_retired_original_selectors() {
    let mut test = Search::new(false, 22, 33, false, false);
    assert_eq!(test.call(1, 0x11).0.al(), 0);
    let mut cookie = [0; 22];
    test.runtime.memory.read(test.base, &mut cookie).unwrap();
    let copy_base = PhysAddr(test.base.0 + 0x200);
    test.runtime.memory.write(copy_base, &cookie).unwrap();
    let copy = test
        .selectors
        .alloc_block(
            copy_base,
            22,
            AccessRights::read_write(),
            &test.runtime.memory,
        )
        .unwrap();
    let new_dta_base = PhysAddr(test.base.0 + 0x300);
    test.runtime
        .memory
        .write(new_dta_base, &[0xa5; 40])
        .unwrap();
    let new_dta = test
        .selectors
        .alloc_block(
            new_dta_base,
            33,
            AccessRights::read_write(),
            &test.runtime.memory,
        )
        .unwrap();
    test.set_dta(1, new_dta.raw().0);
    for selector in [test.fcb, test.dta] {
        let old = test
            .selectors
            .reference(guest_core::Selector(selector))
            .unwrap();
        test.selectors.free_block(old).unwrap();
    }
    test.fcb = copy.raw().0;
    let (regs, result) = test.call(1, 0x12);
    result.unwrap();
    assert_eq!(regs.al(), 0);
    let mut bytes = [0; 12];
    test.runtime.memory.read(new_dta_base, &mut bytes).unwrap();
    assert_eq!(&bytes, b"\x03B       TXT");
    assert_eq!((test.host.search_opens, test.host.search_closes), (1, 1));
}

#[test]
fn fcb_search_protected_recycled_dta_generation_cannot_receive_results() {
    let mut test = Search::new(false, 22, 33, false, false);
    test.call(1, 0x11).1.unwrap();
    let old = test
        .selectors
        .reference(guest_core::Selector(test.dta))
        .unwrap();
    test.selectors.free_block(old).unwrap();
    let new_base = PhysAddr(test.base.0 + 0x300);
    test.runtime.memory.write(new_base, &[0xa5; 40]).unwrap();
    let replacement = test
        .selectors
        .alloc_block(
            new_base,
            33,
            AccessRights::read_write(),
            &test.runtime.memory,
        )
        .unwrap();
    assert_eq!(replacement.raw().0, test.dta);
    let (_, result) = test.call(1, 0x12);
    assert!(result.is_err());
    let mut bytes = [0; 40];
    test.runtime.memory.read(new_base, &mut bytes).unwrap();
    assert_eq!(bytes, [0xa5; 40]);
}

#[test]
fn fcb_search_protected_contexts_are_caller_owned_and_released_on_teardown() {
    let mut test = Search::new(false, 22, 33, false, false);
    test.call(1, 0x11).1.unwrap();
    test.set_dta(2, test.dta);
    assert_eq!(test.call(2, 0x12).0.al(), 0xff);
    {
        let mut memory = Win16DosAddressSpace {
            selectors: &mut test.selectors,
            addresses: &mut test.addresses,
            memory: test.runtime.memory.bus(),
            caller: DosCallerId::new(1).unwrap(),
        };
        test.runtime
            .dos
            .release_caller_address_space(&mut memory, &mut test.host)
            .unwrap();
    }
    test.set_dta(1, test.dta);
    assert_eq!(test.call(1, 0x12).0.al(), 0xff);
}

//! Mutations require only the input FCB, even with a retired DTA selector.
use super::*;

fn input(rename: bool, extended: bool) -> Vec<u8> {
    let mut bytes = vec![0; if rename { 28 } else { 12 }];
    bytes[1..12].copy_from_slice(b"A       TXT");
    if rename {
        bytes[17..28].copy_from_slice(b"B       NEW");
    }
    if extended {
        let mut prefix = vec![0; 7];
        prefix[0] = 0xff;
        prefix.extend(bytes);
        bytes = prefix;
    }
    bytes
}

fn entry(host: &mut ExecHost) {
    host.search_entries.push(DosDirectoryEntry {
        short_name: b"A.TXT".to_vec(),
        attributes: 0x20,
        write_time: 0,
        write_date: 0,
        size: 3,
    });
}

#[test]
fn fcb_mutation_protected_readonly_exact_inputs_ignore_a_retired_dta() {
    for rename in [false, true] {
        for extended in [false, true] {
            let (mut runtime, mut host) = fixture();
            entry(&mut host);
            let bytes = input(rename, extended);
            let base = real_address(runtime.dos.psp_segment(), 0x1000);
            runtime.memory.write(base, &bytes).unwrap();
            let mut selectors = SelectorTable::new().unwrap();
            let data = selectors
                .alloc_block(
                    base,
                    bytes.len() as u32,
                    AccessRights::read_only(),
                    &runtime.memory,
                )
                .unwrap();
            let dta_base = PhysAddr(base.0 + 0x100);
            runtime.memory.write(dta_base, &[0xa5; 40]).unwrap();
            let dta = selectors
                .alloc_block(dta_base, 40, AccessRights::read_write(), &runtime.memory)
                .unwrap();
            let mut addresses = Win16DosCallerAddresses::default();
            {
                let mut memory = Win16DosAddressSpace {
                    selectors: &mut selectors,
                    addresses: &mut addresses,
                    memory: runtime.memory.bus(),
                    caller: DosCallerId::new(1).unwrap(),
                };
                let mut regs = Registers {
                    eax: 0x1a00,
                    ds: dta.raw().0,
                    ..Default::default()
                };
                runtime
                    .dos
                    .interrupt_with_address_space(0x21, &mut regs, &mut memory, &mut host)
                    .unwrap();
            }
            selectors.free_block(dta).unwrap();
            let mut regs = Registers {
                eax: if rename { 0x1234_1707 } else { 0x1234_1307 },
                ds: data.raw().0,
                es: 0xffff,
                ebx: 0xabcd_1234,
                ecx: 0xbcde_2345,
                esi: 0xcdef_3456,
                edi: 0xdef0_4567,
                eflags: 0xad57,
                ..Default::default()
            };
            let mut expected = regs.clone();
            expected.set_al(0);
            {
                let mut memory = Win16DosAddressSpace {
                    selectors: &mut selectors,
                    addresses: &mut addresses,
                    memory: runtime.memory.bus(),
                    caller: DosCallerId::new(1).unwrap(),
                };
                runtime
                    .dos
                    .interrupt_with_address_space(0x21, &mut regs, &mut memory, &mut host)
                    .unwrap();
            }
            assert_eq!(regs, expected);
            let mut actual = vec![0; bytes.len()];
            runtime.memory.read(base, &mut actual).unwrap();
            assert_eq!(actual, bytes);
            let mut guard = [0; 40];
            runtime.memory.read(dta_base, &mut guard).unwrap();
            assert_eq!(guard, [0xa5; 40]);
            assert_eq!((host.search_opens, host.search_closes), (1, 1));
            if rename {
                assert_eq!(host.renamed, [(b"A.TXT".to_vec(), b"B.NEW".to_vec())]);
            } else {
                assert_eq!(host.deleted, [b"A.TXT".to_vec()]);
            }
        }
    }
}

#[test]
fn fcb_mutation_protected_short_inputs_fail_before_native_enumeration() {
    for rename in [false, true] {
        for extended in [false, true] {
            let (mut runtime, mut host) = fixture();
            entry(&mut host);
            let bytes = input(rename, extended);
            let base = real_address(runtime.dos.psp_segment(), 0x1000);
            runtime.memory.write(base, &bytes).unwrap();
            let mut selectors = SelectorTable::new().unwrap();
            let data = selectors
                .alloc_block(
                    base,
                    bytes.len() as u32 - 1,
                    AccessRights::read_only(),
                    &runtime.memory,
                )
                .unwrap();
            let mut addresses = Win16DosCallerAddresses::default();
            let mut regs = Registers {
                eax: if rename { 0x1707 } else { 0x1307 },
                ds: data.raw().0,
                eflags: 0xad57,
                ..Default::default()
            };
            let before = regs.clone();
            let mut memory = Win16DosAddressSpace {
                selectors: &mut selectors,
                addresses: &mut addresses,
                memory: runtime.memory.bus(),
                caller: DosCallerId::new(1).unwrap(),
            };
            assert!(
                runtime
                    .dos
                    .interrupt_with_address_space(0x21, &mut regs, &mut memory, &mut host)
                    .is_err()
            );
            assert_eq!(regs, before);
            assert_eq!(host.search_opens, 0);
            assert!(host.deleted.is_empty() && host.renamed.is_empty());
        }
    }
}

#[test]
fn fcb_mutation_real_mode_inputs_wrap_without_touching_psp_or_dta() {
    for rename in [false, true] {
        for extended in [false, true] {
            let (mut runtime, mut host) = fixture();
            entry(&mut host);
            let bytes = input(rename, extended);
            let segment = runtime.dos.psp_segment() + 0x100;
            for (index, byte) in bytes.iter().enumerate() {
                runtime
                    .memory
                    .write(
                        real_address(segment, 0xfff8u16.wrapping_add(index as u16)),
                        &[*byte],
                    )
                    .unwrap();
            }
            let mut regs = Registers {
                eax: if rename { 0x1707 } else { 0x1307 },
                ds: segment,
                edx: 0xfff8,
                eflags: 0xad57,
                ..Default::default()
            };
            let mut expected = regs.clone();
            expected.set_al(0);
            runtime
                .dos
                .interrupt(0x21, &mut regs, &mut runtime.memory.bus(), &mut host)
                .unwrap();
            assert_eq!(regs, expected);
            for (index, byte) in bytes.iter().enumerate() {
                let mut actual = [0];
                runtime
                    .memory
                    .read(
                        real_address(segment, 0xfff8u16.wrapping_add(index as u16)),
                        &mut actual,
                    )
                    .unwrap();
                assert_eq!(actual[0], *byte);
            }
        }
    }
}

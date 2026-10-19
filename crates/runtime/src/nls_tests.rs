use super::*;
use guest_core::{GuestMemory, MemoryError};

#[test]
fn prc_profile_tables_and_callback_are_read_only_and_do_not_overlap_other_nls_data() {
    let mut memory = Memory::new().unwrap();
    let mut dos = DosKernel::new(crate::MINIMUM_PSP_SEGMENT);
    install(&mut memory, &mut dos).unwrap();
    for (offset, expected) in [
        (PRC_COLLATING_OFFSET, collating_table(CodePage::Cp936).unwrap().as_slice()),
        (PRC_UPPERCASE_OFFSET, upper_case_table(CodePage::Cp936).unwrap().as_slice()),
    ] {
        let address = real_address(NLS_SEGMENT, offset);
        let mut actual = vec![0; expected.len()];
        memory.bus().read(address, &mut actual).unwrap();
        assert_eq!(actual, expected);
        assert!(matches!(memory.bus().write(address, &[0xff]), Err(MemoryError::ReadOnly { .. })));
    }
    let callback = real_address(NLS_SEGMENT, PRC_CASE_MAP_OFFSET);
    assert_eq!(memory.read_u8(callback).unwrap(), 0x9c);
    assert!(matches!(memory.bus().write(callback, &[0]), Err(MemoryError::ReadOnly { .. })));
    assert_eq!(memory.read_u16(real_address(NLS_SEGMENT, COLLATING_OFFSET)).unwrap(), 256);
    assert_eq!(memory.read_u16(real_address(NLS_SEGMENT, UPPERCASE_OFFSET)).unwrap(), 128);
    assert_eq!(memory.read_u16(real_address(NLS_SEGMENT, DBCS_OFFSETS[1].1)).unwrap(), 0xfe81);
}

#[test]
fn dbcs_tables_are_installed_read_only_for_both_supported_code_pages() {
    let mut memory = Memory::new().unwrap();
    let mut dos = DosKernel::new(crate::MINIMUM_PSP_SEGMENT);
    install(&mut memory, &mut dos).unwrap();
    for (code_page, offset) in DBCS_OFFSETS {
        let expected = dbcs_lead_byte_table(code_page);
        let address = real_address(NLS_SEGMENT, offset);
        let mut actual = vec![0; expected.len()];
        memory.bus().read(address, &mut actual).unwrap();
        assert_eq!(actual, expected);
        assert!(matches!(memory.bus().write(address, &[0xff]), Err(MemoryError::ReadOnly { .. })));
        memory.bus().read(address, &mut actual).unwrap();
        assert_eq!(actual, expected);
    }
}

#[test]
fn installed_nls_table_is_in_guest_rom_and_cannot_be_modified_by_guest() {
    let mut memory = Memory::new().unwrap();
    let mut dos = DosKernel::new(crate::MINIMUM_PSP_SEGMENT);
    install(&mut memory, &mut dos).unwrap();
    let address = real_address(NLS_SEGMENT, COLLATING_OFFSET);
    let mut bytes = [0; 258];
    memory.bus().read(address, &mut bytes).unwrap();
    assert_eq!(&bytes, collating_table(CodePage::Cp437).unwrap());
    assert_eq!(u16::from_le_bytes([bytes[0], bytes[1]]), 256);
    assert!(matches!(memory.bus().write(address, &[0]), Err(MemoryError::ReadOnly { .. })));
    assert_eq!(memory.read_u16(address).unwrap(), 256);
    let uppercase_address = real_address(NLS_SEGMENT, UPPERCASE_OFFSET);
    let mut uppercase = [0; 130];
    memory.bus().read(uppercase_address, &mut uppercase).unwrap();
    assert_eq!(&uppercase, upper_case_table(CodePage::Cp437).unwrap());
    assert!(matches!(memory.bus().write(uppercase_address, &[0]), Err(MemoryError::ReadOnly { .. })));
    let callback_address = real_address(NLS_SEGMENT, CASE_MAP_OFFSET);
    assert!(matches!(memory.bus().write(callback_address, &[0]), Err(MemoryError::ReadOnly { .. })));
    assert_eq!(memory.read_u8(callback_address).unwrap(), 0x9c);
}

#[test]
fn dos_image_loading_installs_nls_without_overwriting_firmware() {
    let runtime = crate::Runtime::load(&[0xcd, 0x20], &[], b"C:\\NLS.COM").unwrap();
    assert_eq!(runtime.memory.read_u16(real_address(NLS_SEGMENT, COLLATING_OFFSET)).unwrap(), 256);
    assert_eq!(runtime.memory.read_u8(real_address(crate::XMS_ENTRY.segment, crate::XMS_ENTRY.offset)).unwrap(), 0xcb);
    assert_eq!(runtime.memory.read_u8(real_address(0xf000, 0x1084)).unwrap(), 0xcf);
}

#[test]
fn country_case_map_is_a_real_guest_far_callback_for_all_byte_values() {
    use x86_cpu::{Cpu, StepOutcome};
    use guest_core::Registers;

    let mut memory = Memory::new().unwrap();
    let mut dos = DosKernel::new(crate::MINIMUM_PSP_SEGMENT);
    install(&mut memory, &mut dos).unwrap();
    for (page, callback) in [(CodePage::Cp437, CASE_MAP_OFFSET), (CodePage::Cp936, PRC_CASE_MAP_OFFSET)] {
        // Execute the actual guest callback for each profile, including all bytes.
        let [low, high] = callback.to_le_bytes();
        memory.write(real_address(0x3000, 0x100), &[0x9a, low, high, 0x00, 0xf0]).unwrap();
        for byte in 0..=255u16 {
            let initial = Registers {
                cs: 0x3000, eip: 0x100, ss: 0x2000, esp: 0x6789_fffe,
                ds: 0x1111, es: 0x2222, fs: 0x3333, gs: 0x4444,
                eax: 0xaabb_5a00 | u32::from(byte), ebx: 0x1234_5678,
                ecx: 0x9876_5432, edx: 0xaabb_ccdd, esi: 0x1111_2222,
                edi: 0x3333_4444, ebp: 0x5555_6666, eflags: 0x0603,
            };
            let mut cpu = Cpu::new(initial.clone());
            for _ in 0..16 {
                assert_eq!(cpu.step(&mut memory.bus()).unwrap(), StepOutcome::Continue);
                if cpu.regs.cs == 0x3000 && cpu.regs.eip == 0x105 { break; }
            }
            assert_eq!((cpu.regs.cs, cpu.regs.eip), (0x3000, 0x105));
            let expected = if byte < 0x80 { byte as u8 } else {
                upper_case_table(page).unwrap()[usize::from(byte - 0x80) + 2]
            };
            assert_eq!(cpu.regs.eax, (initial.eax & !0xff) | u32::from(expected));
            assert_eq!((cpu.regs.ebx, cpu.regs.ecx, cpu.regs.edx), (initial.ebx, initial.ecx, initial.edx));
            assert_eq!((cpu.regs.esi, cpu.regs.edi, cpu.regs.ebp), (initial.esi, initial.edi, initial.ebp));
            assert_eq!((cpu.regs.ds, cpu.regs.es, cpu.regs.fs, cpu.regs.gs), (initial.ds, initial.es, initial.fs, initial.gs));
            assert_eq!((cpu.regs.ss, cpu.regs.esp, cpu.regs.eflags), (initial.ss, initial.esp, initial.eflags));
        }
    }
}

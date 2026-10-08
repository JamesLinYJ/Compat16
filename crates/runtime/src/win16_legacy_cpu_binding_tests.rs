use super::*;
use guest_core::PhysAddr;
use win16_abi::AccessRights;

#[test]
fn absent_data_selector_is_saved_opaque_and_new_descriptor_is_stale() {
    let mut selectors = SelectorTable::new().unwrap();
    let raw = 0x0008;
    let SegmentProof::UnmappedData { raw: saved_raw, slot, snapshot } =
        capture_unmapped_data_proof(&selectors, 2, raw).unwrap()
    else { panic!("absent data selector did not produce an opaque proof"); };
    assert_eq!((saved_raw, slot), (raw, 2));
    assert_eq!(snapshot, UnmappedDataSnapshot::Absent);
    validate_unmapped_data_snapshot(&selectors, raw, 2, snapshot).unwrap();

    let installed = selectors.reserve_unbacked().unwrap();
    assert_eq!(installed.raw().0, raw);
    assert!(matches!(
        validate_unmapped_data_snapshot(&selectors, raw, 2, snapshot),
        Err(Win16LegacyCpuBindingError::UnmappedDataChanged { segment: 2 })
    ));
}

#[test]
fn installed_unbacked_data_selector_keeps_its_exact_snapshot() {
    let mut selectors = SelectorTable::new().unwrap();
    let installed = selectors.reserve_unbacked().unwrap();
    let SegmentProof::UnmappedData { raw, slot, snapshot } =
        capture_unmapped_data_proof(&selectors, 3, installed.raw().0).unwrap()
    else { panic!("unbacked data selector did not produce an opaque proof"); };
    assert_eq!((raw, slot), (installed.raw().0, 3));
    assert_eq!(
        snapshot,
        UnmappedDataSnapshot::InstalledUnbacked {
            reference: installed,
            descriptor: selectors.describe(installed).unwrap(),
        }
    );
    validate_unmapped_data_snapshot(&selectors, installed.raw().0, 3, snapshot).unwrap();
}

#[test]
fn unbacked_upgrade_or_replacement_generation_invalidates_saved_data() {
    let mut selectors = SelectorTable::new().unwrap();
    let memory = Memory::new().unwrap();
    let saved = selectors.reserve_unbacked().unwrap();
    let SegmentProof::UnmappedData { snapshot, .. } =
        capture_unmapped_data_proof(&selectors, 4, saved.raw().0).unwrap()
    else { panic!("unbacked data selector did not produce an opaque proof"); };
    let source = selectors.alloc_block(
        PhysAddr(0x1000),
        0x100,
        AccessRights::read_write(),
        &memory,
    ).unwrap();

    selectors.presto_chango_selector(source, saved, &memory).unwrap();
    assert!(matches!(
        validate_unmapped_data_snapshot(&selectors, saved.raw().0, 4, snapshot),
        Err(Win16LegacyCpuBindingError::UnmappedDataChanged { segment: 4 })
    ));

    selectors.free_selector(saved).unwrap();
    let replacement = selectors.reserve_unbacked().unwrap();
    assert_eq!(replacement.raw(), saved.raw());
    assert_ne!(replacement.generation(), saved.generation());
    assert!(matches!(
        validate_unmapped_data_snapshot(&selectors, replacement.raw().0, 4, snapshot),
        Err(Win16LegacyCpuBindingError::UnmappedDataChanged { segment: 4 })
    ));
}

#[test]
fn live_data_selector_low_bit_alias_survives_binding_capture_and_revalidation() {
    let mut runtime = crate::Runtime::load(&tiny_ne_executable(), &[], b"C:\\BINDING.NE").unwrap();
    let mut registers = runtime.cpu.regs.clone();
    let canonical_ds = registers.ds;
    registers.ds |= 0x0003;
    assert_eq!(registers.ds & !0x0007, canonical_ds);
    assert_ne!(registers.ds, canonical_ds);

    let (state_slot, dos, memory) = (&mut runtime.win16, &mut runtime.dos, &mut runtime.memory);
    let state = state_slot.as_mut().expect("NE runtime should own Win16 state");
    let canonical_reference = state.selectors.reference(Selector(canonical_ds)).unwrap();
    let alias_reference = state.selectors.reference(Selector(registers.ds)).unwrap();
    assert_eq!(alias_reference, canonical_reference);

    let mut owner = match state.capture_legacy_cpu_binding_owner(&registers, dos, memory) {
        Ok(owner) => owner,
        Err(error) => panic!("capture live selector owner: {}", error.cause),
    };
    let validation = {
        let binding = Win16LegacyCpuBinding::new(state, memory, &owner);
        let saved = binding.capture(&registers).unwrap();
        assert_eq!(saved.registers.ds, registers.ds);
        let observed = binding.capture(&registers).unwrap();
        let current = binding.capture(&registers).unwrap();
        let target = binding.capture(&registers).unwrap();
        let transfer = LegacyBindingTransfer {
            current: &current,
            target: &target,
            current_registers: &registers,
            target_registers: &registers,
            stack_pointer: LegacyStackPointerTarget::RegisterValue,
        };
        binding.revalidate(&saved, &observed, &transfer)
    };
    state.release_legacy_cpu_binding_owner(&mut owner, dos, memory).unwrap();
    validation.unwrap();
}

#[test]
fn unsupported_absolute_disk_interrupt_keeps_flags_word_and_checked_stack() {
    for vector in [0x25, 0x26] {
        let mut runtime = crate::Runtime::load(&tiny_ne_executable(), &[], b"C:\\STACK.NE").unwrap();
        let original_sp = runtime.cpu.regs.sp();
        let original_bp = runtime.cpu.regs.bp();
        let state = runtime.win16.as_mut().unwrap();
        state.begin_software_interrupt(vector, &mut runtime.cpu, &mut runtime.memory).unwrap();
        assert_eq!(runtime.cpu.regs.sp(), original_sp - 2);
        assert_eq!(runtime.cpu.regs.bp(), original_bp);
        assert!(runtime.cpu.regs.carry());
        let pointer = state.selectors.pointer_from_raw(
            Selector(runtime.cpu.regs.ss), runtime.cpu.regs.sp(),
        ).unwrap();
        let mut flags = [0; 2];
        state.selectors.read(&runtime.memory, pointer, &mut flags).unwrap();
        assert_eq!(u16::from_le_bytes(flags), runtime.cpu.regs.eflags as u16);
        // The caller's POPF consumes precisely this word, leaving the saved
        // BP/DS and its return address at their original offsets.
        runtime.cpu.regs.set_sp(runtime.cpu.regs.sp() + 2);
        assert_eq!(runtime.cpu.regs.sp(), original_sp);

        runtime.cpu.regs.set_sp(1);
        runtime.cpu.regs.set_ax(0x1234);
        runtime.cpu.regs.set_carry(false);
        assert!(state.begin_software_interrupt(vector, &mut runtime.cpu, &mut runtime.memory).is_err());
        assert_eq!(runtime.cpu.regs.sp(), 1);
        assert_eq!(runtime.cpu.regs.ax(), 0x1234);
        assert!(!runtime.cpu.regs.carry());
    }
}

fn tiny_ne_executable() -> Vec<u8> {
    fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    let mut bytes = vec![0; 0x92];
    bytes[0..2].copy_from_slice(b"MZ");
    put_u16(&mut bytes, 0x08, 4);
    bytes[0x3c..0x40].copy_from_slice(&0x40_u32.to_le_bytes());

    let ne = 0x40;
    bytes[ne..ne + 2].copy_from_slice(b"NE");
    put_u16(&mut bytes, ne + 0x04, 0x51); // entry table
    put_u16(&mut bytes, ne + 0x06, 1);
    put_u16(&mut bytes, ne + 0x0e, 2); // automatic data segment
    put_u16(&mut bytes, ne + 0x10, 0x100); // heap reserve
    put_u16(&mut bytes, ne + 0x12, 0x100); // stack reserve
    put_u16(&mut bytes, ne + 0x14, 0); // initial IP
    put_u16(&mut bytes, ne + 0x16, 1); // initial CS
    put_u16(&mut bytes, ne + 0x18, 0x80); // initial SP
    put_u16(&mut bytes, ne + 0x1a, 2); // initial SS
    put_u16(&mut bytes, ne + 0x1c, 2); // segment count
    put_u16(&mut bytes, ne + 0x22, 0x40); // segment table
    put_u16(&mut bytes, ne + 0x26, 0x50); // resident names
    put_u16(&mut bytes, ne + 0x28, 0x51); // module references
    put_u16(&mut bytes, ne + 0x2a, 0x51); // imported names

    // Both segments are zero-filled: executable code followed by writable
    // automatic data. The resident-name and entry tables each have terminators.
    put_u16(&mut bytes, 0x80 + 0x04, 0x0000);
    put_u16(&mut bytes, 0x80 + 0x06, 0x0100);
    put_u16(&mut bytes, 0x88 + 0x04, 0x0001);
    put_u16(&mut bytes, 0x88 + 0x06, 0x0100);
    bytes[0x90] = 0;
    bytes[0x91] = 0;
    bytes
}

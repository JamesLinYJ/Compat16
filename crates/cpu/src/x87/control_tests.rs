use super::{
    environment_width_for_size, get_u16, get_u32, restore_environment, restore_registers,
    save_environment,
};
use crate::x87_state::{Ext80, X87State, X87Tag};

#[test]
fn environment_size_selects_16_and_32_bit_forms() {
    assert_eq!(environment_width_for_size(14), 14);
    assert_eq!(environment_width_for_size(28), 28);
    assert_eq!(environment_width_for_size(94), 14);
    assert_eq!(environment_width_for_size(108), 28);
}

#[test]
fn protected_narrow_environment_keeps_offsets_and_selectors_without_fop() {
    let mut state = X87State {
        instruction_pointer: 0x1234_5678,
        instruction_segment: 0x2468,
        data_pointer: 0x9abc_def0,
        data_segment: 0x1357,
        opcode: 0x05aa,
        ..X87State::default()
    };

    let bytes = save_environment(&state, false, true);
    assert_eq!(get_u16(&bytes, 6), 0x5678);
    assert_eq!(get_u16(&bytes, 8), 0x2468);
    assert_eq!(get_u16(&bytes, 10), 0xdef0);
    assert_eq!(get_u16(&bytes, 12), 0x1357);

    state.reset();
    // The protected 16-bit environment has no FOP field; FLDENV leaves it as
    // architectural state from before the restore.
    state.opcode = 0x1357;
    restore_environment(&mut state, &bytes, false, true);
    assert_eq!(state.instruction_pointer, 0x5678);
    assert_eq!(state.instruction_segment, 0x2468);
    assert_eq!(state.data_pointer, 0xdef0);
    assert_eq!(state.data_segment, 0x1357);
    assert_eq!(state.opcode, 0x1357);
}

#[test]
fn real_narrow_environment_packs_twenty_bit_pointers_and_fop() {
    let mut state = X87State {
        instruction_pointer: 0x5678,
        instruction_segment: 0x1234,
        data_pointer: 0xdef0,
        data_segment: 0x9abc,
        opcode: 0x05aa,
        ..X87State::default()
    };
    let bytes = save_environment(&state, false, false);

    assert_eq!(get_u16(&bytes, 6), 0x79b8);
    assert_eq!(get_u16(&bytes, 8), 0x15aa);
    assert_eq!(get_u16(&bytes, 10), 0x8ab0);
    assert_eq!(get_u16(&bytes, 12), 0xa000);

    state.reset();
    restore_environment(&mut state, &bytes, false, false);
    assert_eq!(state.instruction_pointer, 0x179b8);
    assert_eq!(state.instruction_segment, 0);
    assert_eq!(state.opcode, 0x05aa);
    assert_eq!(state.data_pointer, 0xa8ab0);
    assert_eq!(state.data_segment, 0);
}

#[test]
fn protected_wide_environment_preserves_offset_selectors_and_opcode() {
    let state = X87State {
        instruction_pointer: 0x1234_5678,
        instruction_segment: 0x2468,
        data_pointer: 0x9abc_def0,
        data_segment: 0x1357,
        opcode: 0x05aa,
        ..X87State::default()
    };
    let bytes = save_environment(&state, true, true);

    assert_eq!(get_u32(&bytes, 12), 0x1234_5678);
    assert_eq!(get_u16(&bytes, 16), 0x2468);
    assert_eq!(get_u16(&bytes, 18), 0x05aa);
    assert_eq!(get_u32(&bytes, 20), 0x9abc_def0);
    assert_eq!(get_u16(&bytes, 24), 0x1357);
}

#[test]
fn wide_real_environment_saves_linear_pointers_and_fop() {
    let state = X87State {
        instruction_pointer: 0x5678,
        instruction_segment: 0x1234,
        data_pointer: 0xdef0,
        data_segment: 0x9abc,
        opcode: 0x05aa,
        ..X87State::default()
    };
    let bytes = save_environment(&state, true, false);

    assert_eq!(get_u16(&bytes, 12), 0x79b8);
    assert_eq!(get_u32(&bytes, 16), 0x0000_15aa);
    assert_eq!(get_u16(&bytes, 20), 0x8ab0);
    assert_eq!(get_u32(&bytes, 24), 0x0000_a000);

    let mut restored = X87State::default();
    restore_environment(&mut restored, &bytes, true, false);
    assert_eq!(restored.instruction_pointer, 0x179b8);
    assert_eq!(restored.instruction_segment, 0);
    assert_eq!(restored.opcode, 0x05aa);
    assert_eq!(restored.data_pointer, 0xa8ab0);
    assert_eq!(restored.data_segment, 0);
}

#[test]
fn restore_reclassifies_nonempty_register_tags_from_register_data() {
    let mut state = X87State::default();
    state.set_top(6);
    state.set_tag(7, X87Tag::Valid);
    let mut registers = [0_u8; 80];
    let zero = Ext80::default().to_le_bytes();
    registers[10..20].copy_from_slice(&zero);

    restore_registers(&mut state, &registers);

    assert_eq!(state.tag(6), X87Tag::Empty);
    assert_eq!(state.tag(7), X87Tag::Zero);
}

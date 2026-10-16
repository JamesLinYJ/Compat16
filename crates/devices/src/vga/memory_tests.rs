use super::*;

fn memory_state() -> VgaState {
    let mut state = VgaState::new();
    // VgaState::new enters text mode and seeds character/attribute bytes in
    // planes 0 and 1. These tests program their own contents, so begin with
    // explicitly blank VRAM and latches rather than inherited mode data.
    state.vram.fill(0);
    state.latches = [0; 4];
    state.sequencer[2] = 0x0f;
    state.sequencer[4] = 0x04; // sequential addressing, Chain-4 disabled
    state.graphics[3] = 0;
    state.graphics[4] = 0;
    state.graphics[5] = 0;
    state.graphics[6] = 0;
    state.graphics[7] = 0x0f;
    state.graphics[8] = 0xff;
    state
}

#[test]
fn selected_aperture_maps_and_unmapped_reads_preserve_latches() {
    let mut state = memory_state();
    state.graphics[6] = 0x0c; // B8000-BFFFF, 32 KiB
    state.vram[..4].copy_from_slice(&[0x11, 0x22, 0x33, 0x44]);
    state.latches = [0x77; 4];

    assert_eq!(state.aperture_read(0x17fff), 0xff);
    assert_eq!(state.latches, [0x77; 4]);
    state.aperture_write_byte(0x17fff, 0xaa);
    assert_eq!(&state.vram[..4], &[0x11, 0x22, 0x33, 0x44]);

    assert_eq!(state.aperture_read(0x18000), 0x11);
    assert_eq!(state.latches, [0x11, 0x22, 0x33, 0x44]);
    state.aperture_write_byte(0x18001, 0x5a);
    assert_eq!(&state.vram[4..8], &[0x5a; 4]);
}

#[test]
fn other_aperture_maps_reject_addresses_outside_their_window() {
    let mut state = memory_state();
    for (misc, mapped_start, mapped_end) in [
        (0x00, 0x00000, 0x20000),
        (0x04, 0x00000, 0x10000),
        (0x08, 0x10000, 0x18000),
        (0x0c, 0x18000, 0x20000),
    ] {
        state.graphics[6] = misc;
        state.vram.fill(0);
        let before = state.generation;
        state.aperture_write_byte(mapped_start, 0x35);
        assert_eq!(state.generation, before + 1);
        assert_eq!(state.aperture_read(mapped_start), 0x35);
        if mapped_start != 0 {
            state.aperture_write_byte(mapped_start - 1, 0x91);
            assert_eq!(state.aperture_read(mapped_start - 1), 0xff);
        }
        if mapped_end != 0x20000 {
            state.aperture_write_byte(mapped_end, 0x91);
            assert_eq!(state.aperture_read(mapped_end), 0xff);
        }
    }
}

#[test]
fn read_mode_zero_selects_a_plane_but_loads_all_latches() {
    let mut state = memory_state();
    state.vram[..4].copy_from_slice(&[0x10, 0x21, 0x32, 0x43]);
    state.graphics[4] = 2;

    assert_eq!(state.aperture_read(0), 0x32);
    assert_eq!(state.latches, [0x10, 0x21, 0x32, 0x43]);
}

#[test]
fn read_mode_one_compares_only_selected_planes() {
    let mut state = memory_state();
    state.vram[..4].copy_from_slice(&[0b1010, 0b1100, 0b1000, 0b1110]);
    state.graphics[2] = 0b0010; // expected plane 0 = 0, plane 1 = 1
    state.graphics[7] = 0b0011; // compare planes 0 and 1 only
    state.graphics[5] = 0x08; // read mode 1

    assert_eq!(state.aperture_read(0), 0b0000_0100);
    assert_eq!(state.latches, [0b1010, 0b1100, 0b1000, 0b1110]);

    state.graphics[7] = 0;
    assert_eq!(state.aperture_read(0), 0xff);
}

#[test]
fn read_mode_one_matches_per_pixel_reference_for_every_plane_color_and_mask() {
    let mut state = memory_state();
    state.graphics[5] = 0x08;
    let generation = state.generation;

    for bit in 0..8 {
        let bit_mask = 1_u8 << bit;
        for color in 0_u8..16 {
            let mut latches = [0x55, 0xaa, 0x33, 0xcc];
            for (plane, latch) in latches.iter_mut().enumerate() {
                *latch = (*latch & !bit_mask)
                    | if color & (1 << plane) != 0 { bit_mask } else { 0 };
            }
            state.vram[..4].copy_from_slice(&latches);
            for compare in 0_u8..16 {
                state.graphics[2] = compare;
                for care in 0_u8..16 {
                    state.graphics[7] = care;
                    let expected = read_mode_one_reference(latches, compare, care);
                    assert_eq!(state.aperture_read(0), expected,
                        "bit={bit}, color={color}, compare={compare}, care={care}");
                    assert_eq!(state.latches, latches);
                }
            }
        }
    }
    assert_eq!(state.generation, generation);
}

#[test]
fn read_mode_one_ignores_high_control_bits_and_zero_care_matches_all_pixels() {
    let mut state = memory_state();
    state.graphics[5] = 0x08;
    let latches = [0x55, 0xaa, 0x33, 0xcc];
    state.vram[..4].copy_from_slice(&latches);
    let expected = read_mode_one_reference(latches, 0x05, 0x0a);
    for compare_high in 0_u8..16 {
        state.graphics[2] = (compare_high << 4) | 0x05;
        for care_high in 0_u8..16 {
            state.graphics[7] = (care_high << 4) | 0x0a;
            assert_eq!(state.aperture_read(0), expected);
        }
    }
    for latches in [[0; 4], [0xff; 4], [0x55, 0xaa, 0x33, 0xcc]] {
        state.vram[..4].copy_from_slice(&latches);
        for compare in 0_u8..=255 {
            state.graphics[2] = compare;
            for care in [0x00, 0xf0] {
                state.graphics[7] = care;
                assert_eq!(state.aperture_read(0), 0xff);
                assert_eq!(state.latches, latches);
            }
        }
    }
}

fn read_mode_one_reference(latches: [u8; 4], compare: u8, care: u8) -> u8 {
    let mut result = 0_u8;
    for bit in 0..8 {
        let bit_mask = 1_u8 << bit;
        let mut matches = true;
        for plane in 0..4 {
            if care & (1 << plane) != 0
                && (latches[plane] & bit_mask != 0) != (compare & (1 << plane) != 0)
            {
                matches = false;
                break;
            }
        }
        if matches {
            result |= bit_mask;
        }
    }
    result
}

#[test]
fn chain4_selects_the_low_address_plane_and_obeys_map_mask() {
    let mut state = memory_state();
    state.sequencer[2] = 0x0f;
    state.sequencer[4] = 0x0c; // Chain-4, odd/even disabled
    state.aperture_write_byte(5, 0xa5);
    assert_eq!(state.vram[1 * 4 + 1], 0xa5);
    assert_eq!(state.vram[1 * 4], 0);
    assert_eq!(state.aperture_read(5), 0xa5);

    state.sequencer[2] = 0x01; // selected plane 1 is disabled
    let before = state.generation;
    state.aperture_write_byte(5, 0x5a);
    assert_eq!(state.generation, before);
    assert_eq!(state.vram[1 * 4 + 1], 0xa5);
}

#[test]
fn odd_even_selects_plane_pairs_and_halves_the_memory_address() {
    let mut state = memory_state();
    state.sequencer[4] = 0; // odd/even enabled
    state.graphics[5] = 0x10; // host odd/even read addressing
    state.graphics[6] = 0x02; // replace A0, selecting plane by parity
    state.graphics[4] = 0x02; // read plane pair 2/3
    state.vram[..4].copy_from_slice(&[0x10, 0x20, 0x30, 0x40]);

    assert_eq!(state.aperture_read(0), 0x30);
    assert_eq!(state.aperture_read(1), 0x40);
    assert_eq!(state.vram.get(4..8), Some(&[0, 0, 0, 0][..]));

    state.aperture_write_byte(0, 0x55);
    assert_eq!(&state.vram[..4], &[0x55, 0x20, 0x55, 0x40]);
    state.aperture_write_byte(1, 0xaa);
    assert_eq!(&state.vram[..4], &[0x55, 0xaa, 0x55, 0xaa]);
}

#[test]
fn write_mode_zero_applies_rotate_set_reset_logic_and_bit_mask() {
    let mut state = memory_state();
    state.vram[..4].copy_from_slice(&[0xaa, 0x0f, 0xf0, 0x55]);
    state.aperture_read(0); // load latches
    state.graphics[0] = 0x05; // planes 0 and 2 set
    state.graphics[1] = 0x0f; // use set/reset for every plane
    state.graphics[3] = 0x11; // OR, rotate right one
    state.graphics[5] = 0; // write mode 0
    state.graphics[8] = 0x0f;
    state.aperture_write_byte(1, 0x00); // destination differs from latch source

    assert_eq!(&state.vram[4..8], &[0xaf, 0x0f, 0xff, 0x55]);
}

#[test]
fn write_mode_zero_rotates_cpu_data_and_supports_all_logic_operations() {
    for (operation, expected) in [(0, 0x3c), (1, 0x30), (2, 0xfc), (3, 0xcc)] {
        let mut state = memory_state();
        state.vram[..4].fill(0xf0);
        state.aperture_read(0);
        state.graphics[3] = (operation << 3) | 1; // operation and rotate right one
        state.graphics[5] = 0;
        state.graphics[8] = 0xff;
        state.aperture_write_byte(1, 0x78); // rotated source is 0x3c

        assert_eq!(&state.vram[4..8], &[expected; 4]);
    }
}

#[test]
fn write_mode_one_copies_latches_without_other_write_controls() {
    let mut state = memory_state();
    state.vram[..4].copy_from_slice(&[0x12, 0x34, 0x56, 0x78]);
    state.aperture_read(0);
    state.graphics[5] = 1;
    state.graphics[8] = 0;
    state.graphics[3] = 0x18;
    state.graphics[0] = 0x0f;
    state.graphics[1] = 0x0f;

    state.aperture_write_byte(1, 0xff);
    assert_eq!(&state.vram[..4], &[0x12, 0x34, 0x56, 0x78]);
    assert_eq!(&state.vram[4..8], &[0x12, 0x34, 0x56, 0x78]);
}

#[test]
fn write_mode_two_expands_cpu_data_bits_and_uses_latch_masking() {
    let mut state = memory_state();
    state.vram[..4].copy_from_slice(&[0xaa, 0x0f, 0xf0, 0x55]);
    state.aperture_read(0);
    state.graphics[5] = 2;
    state.graphics[8] = 0xf0;
    state.aperture_write_byte(0, 0x05);

    assert_eq!(&state.vram[..4], &[0xfa, 0x0f, 0xf0, 0x05]);
}

#[test]
fn write_mode_three_uses_rotated_input_only_for_effective_mask() {
    let mut state = memory_state();
    state.vram[..4].copy_from_slice(&[0x00, 0x0f, 0xf0, 0x55]);
    state.aperture_read(0);
    state.graphics[0] = 0x0a; // set/reset planes 1 and 3
    state.graphics[1] = 0; // ignored in write mode 3
    state.graphics[3] = 1; // rotate right one
    state.graphics[5] = 3;
    state.graphics[8] = 0xf0;
    state.aperture_write_byte(0, 0x03); // rotated value is 0x81; mask is 0x80

    assert_eq!(&state.vram[..4], &[0x00, 0x8f, 0x70, 0xd5]);
}

#[test]
fn idempotent_writes_do_not_advance_generation() {
    let mut state = memory_state();
    state.vram[..4].fill(0x5a);
    let generation = state.generation;
    state.aperture_write_byte(0, 0x5a);
    assert_eq!(state.generation, generation);
    state.aperture_write_byte(0x20_000, 0x5a);
    assert_eq!(state.generation, generation);
}

#[test]
fn planar_bios_pixels_use_independent_plane_bytes_and_xor() {
    let mut state = memory_state();
    state.bios_mode = 0x12;
    state.sequencer[2] = 0; // BIOS pixel writes do not use CPU map mask
    let address = 80 + 1;
    state.vram[address * 4 + 1] = 0x40;
    state.vram[address * 4 + 3] = 0x40;
    assert_eq!(state.read_pixel(9, 1, 0), Some(0b1010));

    let generation = state.generation;
    assert!(state.write_pixel(9, 1, 0, 0x82)); // XOR plane 1
    assert_eq!(state.read_pixel(9, 1, 0), Some(0b1000));
    assert_eq!(state.generation, generation + 1);
    assert!(state.write_pixel(9, 1, 0, 0x02)); // bit 7 clear replaces every color plane
    assert_eq!(state.read_pixel(9, 1, 0), Some(0b0010));
}

#[test]
fn chain4_bios_pixels_are_linear_and_never_xor() {
    let mut state = memory_state();
    state.bios_mode = 0x13;
    let linear = 320 + 1;
    state.vram[linear] = 0x24;
    assert_eq!(state.read_pixel(1, 1, 0), Some(0x24));
    assert!(state.write_pixel(1, 1, 0, 0x80));
    assert_eq!(state.read_pixel(1, 1, 0), Some(0x80));
}

#[test]
fn cga_pixels_use_scanline_banks_and_mode_specific_plane_layouts() {
    let mut state = memory_state();
    state.bios_mode = 0x04;
    let odd_line_plane_address = 0x2000 >> 1;
    state.vram[odd_line_plane_address * 4] = 0x0c; // pixel 2 is color 3
    assert_eq!(state.read_pixel(2, 1, 0), Some(3));
    assert!(state.write_pixel(2, 1, 0, 0x81)); // XOR color 1
    assert_eq!(state.read_pixel(2, 1, 0), Some(2));

    state.bios_mode = 0x06;
    assert!(state.write_pixel(8, 1, 0, 1));
    let odd_scanline_byte = 0x2000 + 1;
    assert_ne!(state.vram[odd_scanline_byte * 4] & 0x80, 0);
    assert_eq!(state.read_pixel(8, 1, 0), Some(1));

    let even_line_plane_address = 81;
    assert!(state.write_pixel(8, 2, 0, 1));
    assert_eq!(state.read_pixel(8, 2, 0), Some(1));
    assert_ne!(state.vram[even_line_plane_address * 4] & 0x80, 0);
    assert_eq!(state.vram[even_line_plane_address * 4 + 1], 0);
}

#[test]
fn pixel_helpers_reject_text_out_of_bounds_and_unbacked_pages() {
    let mut state = memory_state();
    state.bios_mode = 0x03;
    assert_eq!(state.read_pixel(0, 0, 0), None);
    assert!(!state.write_pixel(0, 0, 0, 1));

    state.bios_mode = 0x12;
    assert_eq!(state.read_pixel(640, 0, 0), None);
    assert_eq!(state.read_pixel(0, 480, 0), None);
    assert!(!state.write_pixel(0, 0, 2, 1));
}

use super::{ModeKind, mode_info};
use crate::vga::VgaState;

#[test]
fn standard_modes_report_geometry_and_bios_page_strides() {
    let expected: [(u8, u16, u16, u16, u16, u32); 15] = [
        (0x00, 360, 400, 40, 25, 0x0800),
        (0x01, 360, 400, 40, 25, 0x0800),
        (0x02, 720, 400, 80, 25, 0x1000),
        (0x03, 720, 400, 80, 25, 0x1000),
        (0x04, 320, 200, 40, 25, 0x4000),
        (0x05, 320, 200, 40, 25, 0x4000),
        (0x06, 640, 200, 80, 25, 0x4000),
        (0x07, 720, 400, 80, 25, 0x1000),
        (0x0d, 320, 200, 40, 25, 0x2000),
        (0x0e, 640, 200, 80, 25, 0x4000),
        (0x0f, 640, 350, 80, 25, 0x8000),
        (0x10, 640, 350, 80, 25, 0x8000),
        (0x11, 640, 480, 80, 30, 0xa000),
        (0x12, 640, 480, 80, 30, 0xa000),
        (0x13, 320, 200, 40, 25, 0x1_0000),
    ];

    for (mode, width, height, columns, rows, page_bytes) in expected {
        let info = mode_info(mode).expect("listed BIOS mode");
        assert_eq!(info.mode, mode);
        assert_eq!(info.width, width);
        assert_eq!(info.height, height);
        assert_eq!(info.columns, columns);
        assert_eq!(info.rows, rows);
        assert_eq!(info.page_bytes, page_bytes);
    }
    assert_eq!(mode_info(0x0f).unwrap().kind, ModeKind::Planar);
    assert_eq!(mode_info(0x13).unwrap().kind, ModeKind::Chain4);
    assert_eq!(mode_info(0x14), None);
    assert_eq!(mode_info(0x80), None);
}

#[test]
fn text_mode_reset_programs_registers_and_initializes_text_pages() {
    let mut state = VgaState::new();
    state.vram.fill(0xaa);

    assert!(state.set_mode(0x03, true));
    assert_eq!(state.bios_mode, 0x03);
    assert_eq!(state.sequencer, [0x03, 0x00, 0x03, 0x00, 0x02]);
    assert_eq!(state.misc_output, 0x67);
    assert_eq!(&state.vram[..8], &[b' ', 0x07, 0xaa, 0xaa, b' ', 0x07, 0xaa, 0xaa]);
    assert_eq!(state.vram[0x1000 * 4], b' ');
    assert_eq!(state.vram[0x1000 * 4 + 1], 0x07);
    assert_eq!(state.vram[(0x1000 * 4) + 2], 0xaa);
    assert_eq!(state.vram[(0x1000 * 4) + 3], 0xaa);
}

#[test]
fn ega_dac_has_the_full_64_color_set_used_by_attribute_registers() {
    let mut state = VgaState::new();
    assert_eq!(state.palette[0x14], [42, 21, 0]); // brown
    assert_eq!(state.palette[0x38], [21, 21, 21]); // dark gray
    assert_eq!(state.palette[0x3f], [63, 63, 63]);
    assert_eq!(state.palette[0x40], [0, 0, 0]);

    assert!(state.set_mode(0x0f, false));
    assert_eq!(state.palette[0x38], [21, 21, 21]);
}

#[test]
fn mode_13_uses_the_complete_default_dac_palette() {
    let mut state = VgaState::new();
    assert!(state.set_mode(0x13, false));

    assert_eq!(state.palette[0x06], [42, 21, 0]);
    assert_eq!(state.palette[0x10], [0, 0, 0]);
    assert_eq!(state.palette[0x11], [4, 4, 4]);
    assert_eq!(state.palette[0x20], [0, 0, 63]);
    assert_eq!(state.palette[0xf7], [11, 12, 16]);
    assert_eq!(&state.palette[0xf8..], &[[0; 3]; 8]);
}

#[test]
fn mode_06_clear_and_cpu_addressing_use_the_sequential_plane() {
    let mut state = VgaState::new();
    state.vram.fill(0xff);

    assert!(state.set_mode(0x06, true));
    assert_eq!(state.sequencer[4], 0x06); // odd/even disabled
    assert_eq!(state.graphics[6], 0x0d); // B8000h aperture
    assert_eq!(state.vram[0], 0);
    assert_eq!(state.vram[0x3fff * 4], 0);
    assert_eq!(state.vram[0x4000 * 4], 0xff);
    assert_eq!(state.vram[1], 0xff);
    assert_eq!(state.vram[2], 0xff);
    assert_eq!(state.vram[3], 0xff);

    // 640x200x2 uses the 8 KiB odd-scanline bank. x=8 is byte one
    // within that bank, addressed through B8000h + 2001h.
    state.aperture_write_byte(0x18000 + 0x2001, 0x80);
    assert_eq!(state.vram[0x2001 * 4], 0x80);
    assert_eq!(state.vram[0x2001 * 4 + 1], 0xff); // unselected plane is untouched
    assert_eq!(state.read_pixel(8, 1, 0), Some(1));
}

#[test]
fn no_clear_preserves_vram_and_unsupported_modes_leave_state_untouched() {
    let mut state = VgaState::new();
    state.vram[0x1234] = 0xa5;
    let vram_before = state.vram.clone();
    assert!(state.set_mode(0x12, false));
    assert_eq!(state.vram, vram_before);

    let before = state.clone();
    assert!(!state.set_mode(0x14, true));
    assert_eq!(state.sequencer, before.sequencer);
    assert_eq!(state.graphics, before.graphics);
    assert_eq!(state.crtc, before.crtc);
    assert_eq!(state.attribute, before.attribute);
    assert_eq!(state.misc_output, before.misc_output);
    assert_eq!(state.palette, before.palette);
    assert_eq!(state.vram, before.vram);
    assert_eq!(state.bios_mode, before.bios_mode);
    assert_eq!(state.generation, before.generation);
}

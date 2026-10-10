use super::{
    attribute_dac_index, cga_byte, chain4_byte, dac_rgb, expand_dac, render_with_mode_into,
    VgaFrame,
};
use crate::vga::{ModeInfo, ModeKind, VgaDevice, VgaState};

// Keep synthetic mode sizes while exercising the current caller-owned buffer
// renderer. Snapshot construction stays in this test adapter only.
fn render_with_mode(state: &VgaState, mode: ModeInfo) -> Option<VgaFrame> {
    let mut pixels = Vec::new();
    let (width, height) = render_with_mode_into(state, mode, &mut pixels)?;
    Some(VgaFrame { width, height, pixels, generation: state.generation })
}

fn mode(kind: ModeKind, width: u16, height: u16) -> ModeInfo {
    ModeInfo {
        mode: 0x13,
        width,
        height,
        columns: 0,
        rows: 0,
        char_height: 0,
        kind,
        page_bytes: 0,
    }
}

fn state() -> VgaState {
    let mut state = VgaState::new();
    // These small synthetic scanout cases program their own layout. Do not
    // inherit text-mode character bytes, panning, or the BIOS text palette.
    state.vram.fill(0);
    state.crtc.fill(0);
    state.attribute.fill(0);
    state.palette.fill([0; 3]);
    state.attribute[0x10] = 0x40; // direct eight-bit color input
    state.attribute[0x12] = 0x0f; // enable all four attribute planes
    state.pel_mask = 0xff;
    state
}

fn put_dac(state: &mut VgaState, index: usize, rgb: [u8; 3]) {
    state.palette[index] = rgb;
}

#[test]
fn dac_components_expand_six_bits_to_eight() {
    assert_eq!(expand_dac(0), 0);
    assert_eq!(expand_dac(1), 4);
    assert_eq!(expand_dac(0x20), 0x82);
    assert_eq!(expand_dac(0x3f), 0xff);
    assert_eq!(expand_dac(0xff), 0xff);
}

#[test]
fn attribute_palette_and_color_select_form_eight_bit_dac_address() {
    let mut state = state();
    state.attribute[0] = 0x2a;
    state.attribute[0x14] = 0x0d;

    // P54S clear keeps P5:P4 from the palette register; SC7:SC6 provide
    // the two top DAC address bits.
    state.attribute[0x10] = 0;
    assert_eq!(attribute_dac_index(&state, 0), 0xea);

    // P54S set substitutes SC5:SC4 for P5:P4.
    state.attribute[0x10] = 0x80;
    assert_eq!(attribute_dac_index(&state, 0), 0xda);

    state.pel_mask = 0x3f;
    put_dac(&mut state, 0x1a, [63, 32, 1]);
    assert_eq!(dac_rgb(&state, attribute_dac_index(&state, 0)), 0xff_82_04);
}

#[test]
fn planar_pixels_combine_the_four_plane_bits() {
    let mut state = state();
    state.attribute[0x10] = 0;
    state.attribute[0x12] = 0x0f;
    state.attribute[10] = 10;
    state.vram[1] = 0x80;
    state.vram[3] = 0x80;
    put_dac(&mut state, 10, [10, 20, 30]);

    let frame = render_with_mode(&state, mode(ModeKind::Planar, 1, 1)).unwrap();
    assert_eq!(frame.pixels.as_slice(), &[0x28_51_79]);
}

#[test]
fn chain4_uses_interleaved_plane_lanes_and_crtc_start_and_offset() {
    let mut state = state();
    state.bios_mode = 0x13;
    state.crtc[0x0c] = 0;
    state.crtc[0x0d] = 1;
    state.crtc[0x13] = 1;
    state.crtc[0x14] = 0x40; // doubleword addressing
    state.crtc[0x17] = 0x40; // ignored while doubleword mode is set
    for (index, color) in [(4_usize, 5_u8), (5, 6), (6, 7), (7, 8)] {
        put_dac(&mut state, usize::from(color), [color, 0, 0]);
        state.vram[index] = color;
    }
    // Start MA=1 maps to byte 4; Offset=1 advances each row by 8 bytes.
    put_dac(&mut state, 10, [10, 0, 0]);
    state.vram[12] = 10;

    let frame = render_with_mode(&state, mode(ModeKind::Chain4, 4, 2)).unwrap();
    assert_eq!(frame.pixels.as_slice(), &[
        0x14_00_00, 0x18_00_00, 0x1c_00_00, 0x20_00_00,
        0x28_00_00, 0, 0, 0,
    ][..]);
    assert_eq!(frame.generation, state.generation);
}

#[test]
fn cga_packed_bytes_use_odd_even_planes_and_alternating_scanline_banks() {
    let mut state = state();
    state.attribute[0x10] = 0;
    state.attribute[0] = 0;
    state.attribute[1] = 1;
    state.attribute[2] = 2;
    state.attribute[3] = 3;
    for color in 0..4usize {
        put_dac(&mut state, color, [color as u8 * 10, 0, 0]);
    }

    // Packed pixels from logical aperture byte 0 (plane 0) and byte 1
    // (plane 1), each most-significant two-bit pixel first.
    state.vram[0] = 0b10_01_11_00;
    state.vram[1] = 0b00_10_01_11;
    // The second raster line starts at aperture bank 0x2000.
    state.vram[0x1000 * 4] = 0b01_00_00_00;

    assert_eq!(cga_byte(&state, 0), 0b10_01_11_00);
    assert_eq!(cga_byte(&state, 1), 0b00_10_01_11);
    let frame = render_with_mode(&state, mode(ModeKind::Cga2, 8, 2)).unwrap();
    let expected_red: [u8; 16] = [
            81, 40, 121, 0, 0, 81, 40, 121,
            40, 0, 0, 0, 0, 0, 0, 0,
        ];
    let expected = expected_red.map(|red| u32::from(red) << 16);
    assert_eq!(frame.pixels.as_slice(), &expected[..]);
}

#[test]
fn cga1_uses_full_plane_zero_offsets() {
    let mut state = state();
    state.attribute[0x10] = 0;
    state.attribute[0] = 0;
    state.attribute[1] = 1;
    put_dac(&mut state, 1, [0x3f, 0, 0]);
    state.vram[0] = 0x80;
    state.vram[1] = 0x00; // odd/even plane lane is not the Cga1 source
    state.vram[0x2000 * 4] = 0x40;

    let frame = render_with_mode(&state, mode(ModeKind::Cga1, 8, 2)).unwrap();
    assert_eq!(frame.pixels[0], 0xff_00_00);
    assert_eq!(frame.pixels[1], 0);
    assert_eq!(frame.pixels[8], 0);
    assert_eq!(frame.pixels[9], 0xff_00_00);
}

#[test]
fn chain4_direct_pixels_obey_pel_mask() {
    let mut state = state();
    state.crtc[0x14] = 0x40;
    state.attribute[0x10] = 0x40;
    state.pel_mask = 0x0f;
    state.vram[0] = 0x2a;
    put_dac(&mut state, 0x0a, [63, 32, 1]);

    let frame = render_with_mode(&state, mode(ModeKind::Chain4, 1, 1)).unwrap();
    assert_eq!(frame.pixels.as_slice(), &[0xff_82_04]);
}

#[test]
fn chain4_pel_pan_uses_defined_even_values() {
    let mut state = state();
    state.crtc[0x14] = 0x40;
    state.attribute[0x10] = 0x40;
    state.vram[0] = 1;
    state.vram[1] = 2;
    put_dac(&mut state, 1, [1, 0, 0]);
    put_dac(&mut state, 2, [2, 0, 0]);

    state.attribute[0x13] = 1; // low bit is ignored in 256-color mode
    let odd_pan = render_with_mode(&state, mode(ModeKind::Chain4, 1, 1)).unwrap();
    state.attribute[0x13] = 2; // one-pixel shift
    let one_pixel_pan = render_with_mode(&state, mode(ModeKind::Chain4, 1, 1)).unwrap();
    assert_eq!(odd_pan.pixels.as_slice(), &[0x04_00_00]);
    assert_eq!(one_pixel_pan.pixels.as_slice(), &[0x08_00_00]);
}

#[test]
fn text_modes_have_no_graphics_frame() {
    let state = state();
    let mut text = mode(ModeKind::Text, 80, 25);
    text.mode = 3;
    assert!(render_with_mode(&state, text).is_none());

    let device = VgaDevice::new();
    assert!(device.graphics_frame().is_none());
}

#[test]
fn chain4_and_cga_address_helpers_clip_to_vram_aperture() {
    let mut state = state();
    state.vram[0x3ffff] = 0xa5;
    assert_eq!(chain4_byte(&state, 0x3ffff), 0xa5);
    assert_eq!(cga_byte(&state, 0x4000), cga_byte(&state, 0));
}

#[test]
fn bios_pixel_writes_land_at_the_crtc_start_and_stride_for_graphics_modes() {
    let cases = [
        (0x13, ModeKind::Chain4, 320, 200, 0, 1, 0x2a),
        (0x12, ModeKind::Planar, 640, 480, 0, 1, 0x0c),
        (0x04, ModeKind::Cga2, 320, 200, 0, 1, 0x02),
        (0x04, ModeKind::Cga2, 320, 200, 0, 2, 0x03),
        (0x06, ModeKind::Cga1, 640, 200, 0, 1, 0x01),
        (0x06, ModeKind::Cga1, 640, 200, 0, 2, 0x01),
    ];

    for (bios_mode, kind, width, height, x, y, color) in cases {
        let vga = VgaDevice::new();
        assert!(vga.set_mode(bios_mode, true));
        {
            let mut state = vga.borrow_mut();
            let attribute_index = usize::from(color & 0x0f);
            if kind == ModeKind::Chain4 {
                state.attribute[0x10] |= 0x40;
                state.palette[usize::from(color)] = [0x3f, 0, 0];
            } else {
                state.attribute[0x10] &= !0x40;
                state.attribute[attribute_index] = color & 0x0f;
                state.attribute[0x14] = 0;
                state.palette[attribute_index] = [0x3f, 0, 0];
            }
            assert!(state.write_pixel(x, y, 0, color));
        }
        let expected = {
            let state = vga.borrow();
            let raw = state.read_pixel(x, y, 0).unwrap();
            if kind == ModeKind::Chain4 {
                dac_rgb(&state, raw)
            } else {
                dac_rgb(&state, attribute_dac_index(&state, raw))
            }
        };
        let frame = vga.graphics_frame().unwrap();
        assert_eq!(frame.generation, vga.generation());
        assert_eq!((frame.width, frame.height), (width, height));
        let index = usize::from(y) * usize::from(width) + usize::from(x);
        assert_eq!(frame.pixels[index], expected, "mode {bios_mode:#04x}, ({x},{y})");
    }
}

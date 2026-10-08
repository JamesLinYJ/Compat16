//! VGA BIOS DAC reset colors, kept in the hardware's six-bit component range.
//!
//! The 256-color layout is 16 RGBI colors, 16 grays, nine 24-color hue cycles,
//! and eight black entries. This is the VGA BIOS mode 13h layout described in
//! the IBM Personal System/2 Hardware Interface Technical Reference, VGA
//! Function, "256-Color Graphics Mode (Mode Hex 13)".
//!
//! This small const generator is necessary because general color libraries do
//! not provide BIOS palette index order or six-bit quantization. Generate the
//! device values directly, without host color-space conversion or hardware I/O.

const GRAY_LEVELS: [u8; 16] = [0, 5, 8, 11, 14, 17, 20, 24, 28, 32, 36, 40, 45, 50, 56, 63];

// Each brightness group contains three saturation levels. Five channel levels
// describe four steps along a cube edge; the next edge owns the shared
// endpoint, so each hue cycle has 6 * 4 colors.
const HUE_LEVELS: [[u8; 5]; 9] = [
    [0, 16, 31, 47, 63],
    [31, 39, 47, 55, 63],
    [45, 49, 54, 58, 63],
    [0, 7, 14, 21, 28],
    [14, 17, 21, 24, 28],
    [20, 22, 24, 26, 28],
    [0, 4, 8, 12, 16],
    [8, 10, 12, 14, 16],
    [11, 12, 13, 15, 16],
];

pub(crate) const MODE13_DEFAULT_DAC: [[u8; 3]; 256] = mode13_palette();

const fn mode13_palette() -> [[u8; 3]; 256] {
    let mut colors = [[0; 3]; 256];
    let mut index = 0;
    while index < 16 {
        let low = if index & 8 != 0 { 21 } else { 0 };
        let high = if index & 8 != 0 { 63 } else { 42 };
        colors[index] = [
            if index & 4 != 0 { high } else { low },
            if index & 2 != 0 { high } else { low },
            if index & 1 != 0 { high } else { low },
        ];
        index += 1;
    }
    // RGBI's dark yellow slot is brown in the PC BIOS palette.
    colors[6][1] = 21;
    index = 0;
    while index < GRAY_LEVELS.len() {
        colors[16 + index] = [GRAY_LEVELS[index]; 3];
        index += 1;
    }
    let mut cycle = 0;
    while cycle < HUE_LEVELS.len() {
        let mut step = 0;
        while step < 24 {
            colors[32 + cycle * 24 + step] = hue_color(HUE_LEVELS[cycle], step);
            step += 1;
        }
        cycle += 1;
    }
    colors
}

const fn hue_color(levels: [u8; 5], step: usize) -> [u8; 3] {
    // RGB cube corners: blue, magenta, red, yellow, green, cyan. Bits 2, 1, 0
    // select the red, green, blue high endpoint. Each edge changes one channel.
    let corner = [1u8, 5, 4, 6, 2, 3][step / 4];
    let channel = [0usize, 2, 1, 0, 2, 1][step / 4];
    let mut color = [
        levels[if corner & 4 != 0 { 4 } else { 0 }],
        levels[if corner & 2 != 0 { 4 } else { 0 }],
        levels[if corner & 1 != 0 { 4 } else { 0 }],
    ];
    let rising = corner & (4 >> channel) == 0;
    color[channel] = levels[if rising { step % 4 } else { 4 - step % 4 }];
    color
}

/// Reset to the standard 64-color EGA DAC set, or the mode 13h default.
pub(crate) fn reset_dac_palette(palette: &mut [[u8; 3]; 256], mode: u8) {
    palette.fill([0; 3]);

    if mode == 0x13 {
        *palette = MODE13_DEFAULT_DAC;
        return;
    }

    for (index, color) in palette.iter_mut().take(64).enumerate() {
        let component = |high: u8, low: u8| {
            u8::from(index as u8 & high != 0) * 42 + u8::from(index as u8 & low != 0) * 21
        };
        *color = [
            component(0x04, 0x20),
            component(0x02, 0x10),
            component(0x01, 0x08),
        ];
    }
}

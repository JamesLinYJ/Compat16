use super::{Color, DibError, GraphicsError, RasterOp, Rect, Surface};

fn dib_header(width: i32, height: i32, bpp: u16, image_size: u32, colors_used: u32) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&40u32.to_le_bytes());
    bytes.extend_from_slice(&width.to_le_bytes());
    bytes.extend_from_slice(&height.to_le_bytes());
    bytes.extend_from_slice(&1u16.to_le_bytes());
    bytes.extend_from_slice(&bpp.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&image_size.to_le_bytes());
    bytes.extend_from_slice(&0i32.to_le_bytes());
    bytes.extend_from_slice(&0i32.to_le_bytes());
    bytes.extend_from_slice(&colors_used.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes
}

fn rgbquad(bytes: &mut Vec<u8>, red: u8, green: u8, blue: u8) {
    bytes.extend_from_slice(&[blue, green, red, 0]);
}

#[test]
fn parses_packed_one_bit_bottom_up_with_dword_stride() {
    let mut bytes = dib_header(2, 2, 1, 8, 2);
    rgbquad(&mut bytes, 0, 0, 0);
    rgbquad(&mut bytes, 255, 0, 0);
    // Bottom row first. Each one-bit row is padded to four bytes.
    bytes.extend_from_slice(&[0x40, 0, 0, 0, 0x80, 0, 0, 0]);
    let surface = Surface::from_dib(&bytes).unwrap();

    assert_eq!(surface.pixel(0, 0), Some(Color::rgb(255, 0, 0)));
    assert_eq!(surface.pixel(1, 0), Some(Color::rgb(0, 0, 0)));
    assert_eq!(surface.pixel(0, 1), Some(Color::rgb(0, 0, 0)));
    assert_eq!(surface.pixel(1, 1), Some(Color::rgb(255, 0, 0)));
}

#[test]
fn parses_four_and_eight_bit_palette_indices() {
    let mut four_bit = dib_header(2, 1, 4, 4, 2);
    rgbquad(&mut four_bit, 0, 0, 0);
    rgbquad(&mut four_bit, 0, 255, 0);
    four_bit.extend_from_slice(&[0x10, 0, 0, 0]);
    let surface4 = Surface::from_dib(&four_bit).unwrap();
    assert_eq!(surface4.pixel(0, 0), Some(Color::rgb(0, 255, 0)));
    assert_eq!(surface4.pixel(1, 0), Some(Color::rgb(0, 0, 0)));

    let mut eight_bit = dib_header(1, 1, 8, 4, 2);
    rgbquad(&mut eight_bit, 0, 0, 0);
    rgbquad(&mut eight_bit, 0, 0, 255);
    eight_bit.extend_from_slice(&[1, 0, 0, 0]);
    assert_eq!(Surface::from_dib(&eight_bit).unwrap().pixel(0, 0), Some(Color::rgb(0, 0, 255)));
}

#[test]
fn parses_top_down_24_bit_bgr_and_ignores_32_bit_reserved_alpha() {
    let mut top_down = dib_header(1, -2, 24, 8, 0);
    top_down.extend_from_slice(&[3, 2, 1, 0, 6, 5, 4, 0]);
    let surface = Surface::from_dib(&top_down).unwrap();
    assert_eq!(surface.pixel(0, 0), Some(Color::rgb(1, 2, 3)));
    assert_eq!(surface.pixel(0, 1), Some(Color::rgb(4, 5, 6)));

    let mut bgra = dib_header(1, 1, 32, 4, 0);
    bgra.extend_from_slice(&[30, 20, 10, 0]);
    assert_eq!(Surface::from_dib(&bgra).unwrap().pixel(0, 0), Some(Color::rgb(10, 20, 30)));
}

#[test]
fn rejects_truncated_rows_unsupported_compression_and_short_palette() {
    let bytes = dib_header(1, 1, 24, 0, 0);
    assert_eq!(Surface::from_dib(&bytes), Err(DibError::Truncated));

    let mut compressed = dib_header(1, 1, 24, 4, 0);
    compressed[16..20].copy_from_slice(&1u32.to_le_bytes());
    compressed.extend_from_slice(&[0; 4]);
    assert_eq!(Surface::from_dib(&compressed), Err(DibError::UnsupportedCompression(1)));

    let mut short_palette = dib_header(1, 1, 8, 4, 1);
    rgbquad(&mut short_palette, 0, 0, 0);
    short_palette.extend_from_slice(&[1, 0, 0, 0]);
    assert_eq!(Surface::from_dib(&short_palette), Err(DibError::InvalidPaletteIndex(1)));
}

#[test]
fn blit_clips_both_sources_and_destinations_and_rejects_other_rops_atomically() {
    let mut source = Surface::new(2, 2, Color::BLACK).unwrap();
    source.set_pixel(0, 0, Color::rgb(1, 0, 0));
    source.set_pixel(1, 0, Color::rgb(2, 0, 0));
    source.set_pixel(0, 1, Color::rgb(3, 0, 0));
    source.set_pixel(1, 1, Color::rgb(4, 0, 0));
    let mut dest = Surface::new(2, 2, Color::WHITE).unwrap();
    let copied = dest.bit_blt(-1, 0, &source, 0, 0, 2, 2, None, RasterOp::SrcCopy).unwrap();
    assert_eq!(copied, Rect::new(0, 0, 1, 2));
    assert_eq!(dest.pixel(0, 0), Some(Color::rgb(2, 0, 0)));
    assert_eq!(dest.pixel(0, 1), Some(Color::rgb(4, 0, 0)));

    let before = dest.clone();
    assert_eq!(
        dest.bit_blt(0, 0, &source, 0, 0, 2, 2, None, RasterOp::Unsupported(0x00cc_0020)),
        Err(GraphicsError::UnsupportedRasterOperation(0x00cc_0020)),
    );
    assert_eq!(dest, before);
}

#[test]
fn overlapping_self_blit_uses_memmove_order() {
    let mut surface = Surface::new(1, 4, Color::BLACK).unwrap();
    for y in 0..4 {
        surface.set_pixel(0, y, Color::rgb(y as u8 + 1, 0, 0));
    }
    surface.bit_blt_within(0, 1, 0, 0, 1, 3, None, RasterOp::SrcCopy).unwrap();
    assert_eq!(
        surface.pixels().iter().map(|color| color.red).collect::<Vec<_>>(),
        vec![1, 1, 2, 3],
    );
}

#[test]
fn dimension_limits_are_checked_before_allocation() {
    assert_eq!(Surface::new(0, 1, Color::BLACK), Err(GraphicsError::InvalidDimensions));
    assert_eq!(Surface::new(u32::MAX, u32::MAX, Color::BLACK), Err(GraphicsError::SurfaceTooLarge));
}

#[test]
fn graphics_and_dib_errors_include_readable_numeric_context() {
    assert_eq!(
        GraphicsError::UnsupportedRasterOperation(0x00cc_0020).to_string(),
        "Raster operation 0x00CC0020 is not supported."
    );
    assert_eq!(
        DibError::UnsupportedBitDepth(16).to_string(),
        "DIB pixel depth of 16 bits is not supported."
    );
    assert_eq!(
        DibError::InvalidPaletteIndex(7).to_string(),
        "DIB pixel references palette index 7, which is outside the palette."
    );
}

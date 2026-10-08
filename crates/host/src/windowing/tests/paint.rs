use super::super::paint::OwnedDib;
use graphics::{Color, Surface};

#[test]
fn surface_conversion_uses_owned_top_down_bgra_pixels() {
    let surface = Surface::from_pixels(
        2,
        1,
        vec![Color::rgb(1, 2, 3), Color::rgb(0x11, 0x22, 0x33)],
    )
    .unwrap();
    let dib = OwnedDib::from_surface(&surface).unwrap();
    assert_eq!((dib.width, dib.height), (2, 1));
    assert_eq!(dib.bgra, [3, 2, 1, 0, 0x33, 0x22, 0x11, 0]);
    let info = dib.bitmap_info();
    assert_eq!(info.bmiHeader.biWidth, 2);
    assert_eq!(info.bmiHeader.biHeight, -1);
    assert_eq!(info.bmiHeader.biBitCount, 32);
    assert_eq!(info.bmiHeader.biSizeImage, 8);
}

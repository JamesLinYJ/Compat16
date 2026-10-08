use super::{BitmapHandle, Gdi, GdiError};
use crate::{Color, GraphicsError, RasterOp};

#[test]
fn selection_and_deletion_validate_typed_handles_and_ownership() {
    let mut gdi = Gdi::new();
    let dc1 = gdi.create_device_context().unwrap();
    let dc2 = gdi.create_device_context().unwrap();
    let bitmap = gdi.create_bitmap(1, 1, Color::WHITE).unwrap();

    assert_eq!(gdi.select_bitmap(dc1, Some(bitmap)), Ok(None));
    assert_eq!(gdi.delete_bitmap(bitmap), Err(GdiError::BitmapStillSelected(bitmap)));
    assert_eq!(gdi.select_bitmap(dc2, Some(bitmap)), Err(GdiError::BitmapAlreadySelected(bitmap)));
    gdi.delete_device_context(dc1).unwrap();
    gdi.delete_bitmap(bitmap).unwrap();
    let next = gdi.create_bitmap(1, 1, Color::BLACK).unwrap();
    assert_ne!(bitmap, next);
    assert_eq!(gdi.bitmap_surface(bitmap), Err(GdiError::InvalidBitmap(bitmap)));
}

#[test]
fn dc_bitblt_obeys_clip_and_supports_self_overlap() {
    let mut gdi = Gdi::new();
    let dc = gdi.create_device_context().unwrap();
    let bitmap = gdi.create_bitmap(1, 4, Color::BLACK).unwrap();
    gdi.select_bitmap(dc, Some(bitmap)).unwrap();
    for y in 0..4 {
        gdi.bitmap_surface_mut(bitmap).unwrap().set_pixel(0, y, Color::rgb(y as u8 + 1, 0, 0));
    }
    gdi.set_clip_rect(dc, Some(crate::Rect::new(0, 1, 1, 4))).unwrap();
    gdi.bit_blt(dc, 0, 1, dc, 0, 0, 1, 3, RasterOp::SrcCopy).unwrap();
    assert_eq!(
        gdi.bitmap_surface(bitmap).unwrap().pixels().iter().map(|c| c.red).collect::<Vec<_>>(),
        vec![1, 1, 2, 3],
    );
    assert_eq!(gdi.selected_bitmap(dc), Ok(Some(bitmap)));
}

#[test]
fn invalid_numeric_bitmap_handle_does_not_resolve() {
    let mut gdi = Gdi::new();
    let invalid = BitmapHandle::from_raw(99).unwrap();
    assert_eq!(gdi.delete_bitmap(invalid), Err(GdiError::InvalidBitmap(invalid)));
}

#[test]
fn gdi_error_text_keeps_handle_and_nested_error_context() {
    let bitmap = BitmapHandle::from_raw(0x1234).unwrap();
    let invalid_bitmap = GdiError::InvalidBitmap(bitmap);
    assert_eq!(
        invalid_bitmap.to_string(),
        "GDI bitmap 0x1234 is invalid or no longer exists."
    );

    let nested = GdiError::Graphics(GraphicsError::UnsupportedRasterOperation(0x00cc_0020));
    assert_eq!(
        nested.to_string(),
        "GDI drawing operation failed: Raster operation 0x00CC0020 is not supported."
    );
    assert_eq!(
        std::error::Error::source(&nested).unwrap().to_string(),
        "Raster operation 0x00CC0020 is not supported."
    );

    let exhausted = GdiError::HandleExhausted;
    assert_eq!(
        std::error::Error::source(&exhausted).unwrap().to_string(),
        "No unused 16-bit object handles remain; valid handles range from 1 through 65,535."
    );
}

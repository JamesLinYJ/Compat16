use super::{rect_extent, WindowingError};
use graphics::{Rect, WindowHandle};

mod events;
mod paint;

#[test]
fn outer_window_rectangle_becomes_checked_dimensions() {
    assert_eq!(rect_extent(Rect::new(-20, 10, 180, 90)), Ok((200, 80)));
    assert_eq!(rect_extent(Rect::new(5, 5, 5, 5)), Ok((0, 0)));
}

#[test]
fn invalid_and_overflowing_rectangles_are_rejected() {
    assert_eq!(
        rect_extent(Rect::new(2, 0, 1, 1)),
        Err(WindowingError::InvalidRectangle),
    );
    assert_eq!(
        rect_extent(Rect::new(i32::MIN, 0, i32::MAX, 1)),
        Err(WindowingError::InvalidRectangle),
    );
}

#[test]
fn windowing_errors_include_native_code_and_host_handle() {
    assert_eq!(
        WindowingError::Native {
            operation: "CreateWindowExW",
            code: Some(5),
        }
        .to_string(),
        "Windows API operation CreateWindowExW failed with error code 5 (0x00000005)."
    );
    let handle = WindowHandle::from_raw(0x1234).unwrap();
    assert_eq!(
        WindowingError::UnknownWindow(handle).to_string(),
        "Host window handle 0x1234 is not registered."
    );
}

//! Opt-in native checks of class-resource token type and retirement.

use super::*;
use crate::windows::guest_text::GuestTextCodec;

#[test]
#[ignore = "requires native Windows USER and GDI; no interactive input"]
fn class_resource_resolvers_reject_wrong_types_and_retired_tokens() {
    let images = Win16Images::new(GuestTextCodec::new(1252).unwrap());
    let icon = images.system_icon(32512).unwrap().unwrap();
    let cursor = images.system_cursor(32512).unwrap().unwrap();
    assert_ne!(resolve_icon(Some(icon), &images).unwrap().unwrap(), 0);
    assert_ne!(resolve_cursor(Some(cursor), &images).unwrap().unwrap(), 0);
    assert_eq!(resolve_icon(None, &images).unwrap(), Some(0));
    assert_eq!(resolve_cursor(None, &images).unwrap(), Some(0));
    assert_eq!(resolve_icon(Some(Win16HostIcon(cursor.0)), &images).unwrap(), None);
    assert_eq!(resolve_cursor(Some(Win16HostCursor(icon.0)), &images).unwrap(), None);
    images.release_icon(icon).unwrap();
    images.release_cursor(cursor).unwrap();
    assert_eq!(resolve_icon(Some(icon), &images).unwrap(), None);
    assert_eq!(resolve_cursor(Some(cursor), &images).unwrap(), None);

    let mut objects = Win16Objects::new();
    let brush = objects.create_solid_brush(0x00_332211).unwrap().unwrap();
    let region = objects.create_region().unwrap().unwrap();
    let background = Some(Win16ClassBackground::Brush(brush));
    assert_ne!(resolve_background(background, &objects).map(|value| value.handle).unwrap(), 0);
    assert_eq!(resolve_background(Some(Win16ClassBackground::Brush(region)), &objects).map(|value| value.handle), None);
    assert_eq!(resolve_background(None, &objects).map(|value| value.handle), Some(0));
    assert_ne!(resolve_background(Some(Win16ClassBackground::SystemColor(5)), &objects).map(|value| value.handle).unwrap(), 0);
    assert!(objects.delete(brush));
    assert_eq!(resolve_background(background, &objects).map(|value| value.handle), None);
}

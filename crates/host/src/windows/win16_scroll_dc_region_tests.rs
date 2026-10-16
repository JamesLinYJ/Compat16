//! ScrollDC output routing and independent HRGN identity checks; no desktop UI.

use super::*;
use runtime::{Win16HostDc, Win16HostUpdateOperation, Win16HostUpdateResult, Win16WindowResult};
use windows_sys::Win32::Foundation::RECT;
use windows_sys::Win32::Graphics::Gdi::{GetRgnBox, SetRectRgn, NULLREGION, SIMPLEREGION};

fn operation(region: Option<Win16HostGdiObject>) -> Win16WindowOperation {
    Win16WindowOperation::UpdateRegion(Win16HostUpdateOperation::ScrollDC {
        dc: Win16HostDc(7), dx: -7, dy: 9, scroll_rect: None, clip_rect: None,
        update_region: region, update_rect_is_null: false,
    })
}

#[test]
fn scroll_dc_region_routes_exact_optional_output_token() {
    assert_eq!(update_region_output(&operation(None)), None);
    assert!(update_region_tokens(&operation(None)).is_empty());
    let token = Win16HostGdiObject(123);
    assert_eq!(update_region_output(&operation(Some(token))), Some(token));
    assert_eq!(update_region_tokens(&operation(Some(token))), [token].into_iter().collect());
}

fn result(value: u16) -> Win16WindowResult {
    Win16WindowResult::UpdateRegion(Win16HostUpdateResult::Rect { value, rect: None })
}

#[test]
fn scroll_dc_region_snapshot_commits_only_after_success() {
    let mut objects = Win16Objects::new();
    let token = objects.create_region().unwrap().unwrap();
    let original = objects.native_region(token).unwrap();
    let snapshot = objects.lease_region(token).unwrap().unwrap();
    assert_ne!(snapshot.native(), original);
    // SAFETY: The two regions are independently owned for this synchronous test.
    assert_ne!(unsafe { SetRectRgn(snapshot.native(), -8, -4, 12, 20) }, 0);
    let mut bounds = RECT::default();
    assert_eq!(unsafe { GetRgnBox(original, &mut bounds) }, NULLREGION);
    commit_update_region(&objects, token, &snapshot, &mut result(0)).unwrap();
    assert_eq!(unsafe { GetRgnBox(original, &mut bounds) }, NULLREGION);
    commit_update_region(&objects, token, &snapshot, &mut result(1)).unwrap();
    assert_eq!(unsafe { GetRgnBox(original, &mut bounds) }, SIMPLEREGION);
    assert_eq!((bounds.left, bounds.top, bounds.right, bounds.bottom), (-8, -4, 12, 20));
}

#[test]
fn scroll_dc_region_retired_identity_never_overwrites_replacement() {
    let mut objects = Win16Objects::new();
    let token = objects.create_region().unwrap().unwrap();
    let snapshot = objects.lease_region(token).unwrap().unwrap();
    // SAFETY: This is the independent snapshot owned throughout the test.
    assert_ne!(unsafe { SetRectRgn(snapshot.native(), 1, 2, 30, 40) }, 0);
    assert!(objects.delete(token));
    let replacement = objects.create_region().unwrap().unwrap();
    assert_ne!(token, replacement);
    commit_update_region(&objects, token, &snapshot, &mut result(1)).unwrap();
    let mut bounds = RECT::default();
    assert_eq!(unsafe { GetRgnBox(objects.native_region(replacement).unwrap(), &mut bounds) }, NULLREGION);
    // A mismatched token is rejected even if it resolves to a valid live HRGN.
    assert!(commit_update_region(&objects, replacement, &snapshot, &mut result(1)).is_err());
    assert_eq!(unsafe { GetRgnBox(objects.native_region(replacement).unwrap(), &mut bounds) }, NULLREGION);
}

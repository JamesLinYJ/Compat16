//! Opt-in native differential checks for public SetParent, distinct from fields.

use super::*;
use windows_sys::Win32::UI::WindowsAndMessaging::{GetAncestor, GetWindow, GA_PARENT, GW_OWNER};

fn public_reparent(state: &SharedWorker, child: Win16HostWindow, parent: Win16WindowTarget)
    -> Win16WindowDataResult
{
    execute(state, Win16WindowDataCall::Reparent {
        window: Win16WindowTarget::Mapped(child), parent,
    }).unwrap()
}

#[test]
#[ignore = "requires a Windows USER desktop; creates hidden native windows"]
fn public_set_parent_preserves_native_desktop_null_and_style_conventions() {
    run_on_worker(|state| {
        let windows = NativeWindows::new(state);
        let owner = windows.window(ptr::null_mut(), WS_POPUP);
        let parent = windows.window(ptr::null_mut(), WS_POPUP);
        for style in [0, WS_POPUP, WS_CHILD] {
            let initial = if style == WS_CHILD { parent.1 } else { owner.1 };
            let direct = windows.window(initial, style);
            let bridged = windows.window(initial, style);
            for destination in [parent.1, ptr::null_mut(), parent.1] {
                let before = unsafe { GetAncestor(bridged.1, GA_PARENT) };
                let before_style = read_scalar(bridged.1, Win16WindowDataField::Style).unwrap();
                unsafe { SetLastError(0) };
                let direct_previous = unsafe { SetParent(direct.1, destination) };
                let direct_error = unsafe { GetLastError() };
                let result = public_reparent(state, bridged.0, if destination.is_null() {
                    Win16WindowTarget::Null
                } else { Win16WindowTarget::Mapped(parent.0) });
                let Win16WindowDataResult::ParentMutation { attempted, succeeded, previous } = result
                    else { panic!("expected immutable mutation outcome"); };
                assert!(attempted);
                assert_eq!(succeeded, !direct_previous.is_null() || direct_error == 0);
                // Native return is authoritative: a desktop snapshot does not
                // manufacture a desktop return when SetParent returns NULL.
                let expected = if succeeded && !direct_previous.is_null() && direct_previous == before {
                    Some(worker::token_for_native(state, direct_previous).unwrap())
                } else { None };
                assert_eq!(previous, expected);
                assert_eq!(unsafe { GetAncestor(bridged.1, GA_PARENT) },
                    unsafe { GetAncestor(direct.1, GA_PARENT) });
                assert_eq!(unsafe { GetWindow(bridged.1, GW_OWNER) },
                    unsafe { GetWindow(direct.1, GW_OWNER) });
                assert_eq!(read_scalar(bridged.1, Win16WindowDataField::Style), Some(before_style));
                let actual_parent = unsafe { GetAncestor(bridged.1, GA_PARENT) };
                let expected_parent = if actual_parent.is_null() { None }
                    else { Some(worker::token_for_native(state, actual_parent).unwrap()) };
                assert_eq!(query_parent(state, bridged.0).unwrap(),
                    Win16HostWindowParentObservation::Live { child_parent: expected_parent });
            }
        }
    });
}

#[test]
#[ignore = "requires a Windows USER desktop; creates hidden native windows"]
fn popup_actual_parent_is_distinct_from_legacy_owner_field() {
    run_on_worker(|state| {
        let windows = NativeWindows::new(state);
        let owner = windows.window(ptr::null_mut(), WS_POPUP);
        let parent = windows.window(ptr::null_mut(), WS_POPUP);
        let popup = windows.window(owner.1, WS_POPUP);
        assert!(matches!(public_reparent(state, popup.0, Win16WindowTarget::Mapped(parent.0)),
            Win16WindowDataResult::ParentMutation { attempted: true, succeeded: true, .. }));
        assert_eq!(unsafe { GetAncestor(popup.1, GA_PARENT) }, parent.1);
        assert_eq!(query_parent(state, popup.0).unwrap(),
            Win16HostWindowParentObservation::Live { child_parent: Some(parent.0) });
        assert_eq!(read_scalar(popup.1, Win16WindowDataField::Style).unwrap() & WS_CHILD, 0);
        let other_owner = windows.window(ptr::null_mut(), WS_POPUP);
        let old_field = read_parent(popup.1).unwrap();
        let result = reparent(state, popup.0, Win16WindowTarget::Mapped(other_owner.0));
        assert!(matches!(result, Win16WindowDataResult::ParentMutation {
            attempted: true, succeeded: true, previous,
        } if previous == token_for_native(state, old_field).unwrap()));
        assert_eq!(unsafe { GetAncestor(popup.1, GA_PARENT) }, parent.1);
    });
}

#[test]
#[ignore = "requires a Windows USER desktop; creates hidden native windows"]
fn destroy_receipts_cover_popup_actual_parent_and_owner_edges() {
    run_on_worker(|state| {
        let windows = NativeWindows::new(state);
        let root = windows.window(ptr::null_mut(), WS_POPUP);
        let actual_child = windows.window(ptr::null_mut(), WS_POPUP);
        let owned = windows.window(root.1, WS_POPUP);
        let survivor = windows.window(ptr::null_mut(), WS_POPUP);
        assert!(matches!(public_reparent(state, actual_child.0, Win16WindowTarget::Mapped(root.0)),
            Win16WindowDataResult::ParentMutation { succeeded: true, .. }));
        assert_eq!(unsafe { GetAncestor(actual_child.1, GA_PARENT) }, root.1);
        assert_eq!(unsafe { GetWindow(owned.1, GW_OWNER) }, root.1);
        let (succeeded, batch) = worker::destroy_window_operation(state, root.0);
        assert!(succeeded);
        for expected in [root.0, actual_child.0, owned.0] {
            assert!(batch.receipts.iter().any(|receipt| receipt.window == expected));
            assert_eq!(identity::liveness(state, expected).unwrap(), Win16HostWindowLiveness::Retired);
        }
        assert!(batch.receipts.iter().all(|receipt| receipt.window != survivor.0));
        assert_eq!(identity::liveness(state, survivor.0).unwrap(), Win16HostWindowLiveness::Live);
    });
}

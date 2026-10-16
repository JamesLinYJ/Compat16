//! Opt-in native USER query tests. These create hidden native window trees on
//! the real USER worker and therefore stay out of headless/default CI. Run on
//! a suitable Windows desktop with:
//! cargo test -p host-services child_queries_tests -- --ignored --test-threads=1

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::time::Duration;

use runtime::{
    Win16CreationId, Win16HostClass, Win16HostClassName, Win16HostClassSpec,
    Win16HostCreationData, Win16HostPoint, Win16HostSystemClass, Win16HostWindow,
    Win16WindowCall, Win16WindowCallResult, Win16WindowInsertAfter, Win16WindowOperation,
    Win16WindowResult, Win16WindowStep, Win16WindowTarget,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    SWP_NOACTIVATE, SWP_NOMOVE, SWP_NOSIZE, WS_CHILD, WS_DISABLED, WS_EX_TRANSPARENT,
    WS_POPUP, WS_VISIBLE,
};

use super::super::win16_window_worker::{NativeDropRetirementQueue, WindowWorker, WorkerCommand};
use crate::windows::{
    guest_text::GuestTextCodec, win16_gdi::Win16Dcs, win16_images::Win16Images,
};

const CLASS: Win16HostClass = Win16HostClass(1);
const SKIP_INVISIBLE: u16 = 1;
const SKIP_DISABLED: u16 = 2;
const SKIP_TRANSPARENT: u16 = 4;

struct NativeQueries {
    worker: WindowWorker,
    identities: Arc<AtomicU64>,
}

impl NativeQueries {
    fn new() -> Self {
        let codec = GuestTextCodec::new(1252).expect("create guest ANSI codec");
        let identities = Arc::new(AtomicU64::new(1));
        let worker = WindowWorker::spawn(
            Win16Dcs::with_text_codec(codec),
            Win16Images::new(codec),
            Arc::clone(&identities),
            codec,
            NativeDropRetirementQueue::shared(),
        ).expect("start native USER test worker");
        let (response, receive) = mpsc::channel();
        worker.send(WorkerCommand::RegisterClass {
            class: CLASS,
            spec: Win16HostClassSpec {
                style: 0,
                class_extra: 0,
                window_extra: 0,
                icon: None,
                cursor: None,
                background: None,
                system_class: Some(Win16HostSystemClass::Static),
            },
            icon: 0,
            cursor: 0,
            background: 0,
            response,
        }).unwrap_or_else(|_| panic!("send predefined class registration"));
        assert!(receive.recv_timeout(Duration::from_secs(10))
            .expect("receive predefined class registration")
            .expect("register predefined class").is_some());
        Self { worker, identities }
    }

    fn next_id(&self) -> u64 {
        self.identities.fetch_add(1, Ordering::Relaxed)
    }

    fn operation(&self, operation: Win16WindowOperation) -> Win16WindowResult {
        let (response, receive) = mpsc::channel();
        self.worker.send(WorkerCommand::Begin {
            id: self.next_id(),
            operation,
            win_exec: None,
            control_color_return: None,
            native_bitmaps: BTreeMap::new(),
            native_font: None,
            toolbar_bitmap_leases: BTreeMap::new(),
            native_regions: BTreeMap::new(),
            gray_string_brush: None,
            response,
        }).unwrap_or_else(|_| panic!("send native USER query operation"));
        match receive.recv_timeout(Duration::from_secs(10))
            .expect("receive native USER query operation")
            .expect("execute native USER query operation")
        {
            Win16WindowStep::Complete(result) => result,
            step => panic!("predefined controls must complete without guest callbacks: {step:?}"),
        }
    }

    fn call(&self, call: Win16WindowCall) -> Win16WindowCallResult {
        match self.operation(Win16WindowOperation::WindowCall(call)) {
            Win16WindowResult::WindowCall(result) => result,
            result => panic!("unexpected window-query result: {result:?}"),
        }
    }

    fn window(
        &self,
        parent: Option<Win16HostWindow>,
        rect: [i16; 4],
        style: u32,
        ex_style: u32,
    ) -> Win16HostWindow {
        let [x, y, width, height] = rect;
        match self.operation(Win16WindowOperation::Create {
            creation: Win16CreationId(self.next_id()),
            data: Win16HostCreationData {
                class: CLASS,
                guest_instance: 0,
                guest_class_name: Win16HostClassName::Name(b"STATIC".to_vec()),
                guest_menu: 0,
                class_menu_template: None,
                create_parameter: 0,
                creation_data: None,
                mdi_client: None,
                dialog_root: false,
                menu: None,
                title: Some(b"Child window query test".to_vec()),
                style,
                ex_style,
                x, y, width, height,
                parent,
                child_id: (style & WS_CHILD != 0).then_some(0),
            },
        }) {
            Win16WindowResult::Created(result) => result.live_window
                .expect("create a live predefined native test window"),
            result => panic!("unexpected native creation result: {result:?}"),
        }
    }

    fn root(&self) -> Win16HostWindow {
        // A nonzero screen origin makes accidental screen-coordinate testing
        // fail. The root is never shown or activated by this fixture.
        self.window(None, [400, 300, 240, 180], WS_POPUP, 0)
    }

    fn top(&self, window: Win16HostWindow) {
        assert!(matches!(self.call(Win16WindowCall::SetWindowPos {
            window: Win16WindowTarget::Mapped(window),
            insert_after: Win16WindowInsertAfter::Top,
            x: 0, y: 0, width: 0, height: 0,
            flags: (SWP_NOACTIVATE | SWP_NOMOVE | SWP_NOSIZE) as u16,
        }), Win16WindowCallResult::Boolean(true)));
    }

    fn hit(
        &self,
        parent: Win16WindowTarget,
        point: [i32; 2],
        flags: Option<u16>,
    ) -> Option<Win16HostWindow> {
        let point = Win16HostPoint { x: point[0], y: point[1] };
        let call = match flags {
            None => Win16WindowCall::ChildWindowFromPoint { parent, point },
            Some(flags) => Win16WindowCall::ChildWindowFromPointEx { parent, point, flags },
        };
        match self.call(call) {
            Win16WindowCallResult::Window(result) => result,
            result => panic!("unexpected native hit-test result: {result:?}"),
        }
    }

    fn is_child(&self, parent: Win16WindowTarget, child: Win16WindowTarget) -> bool {
        match self.call(Win16WindowCall::IsChild { parent, child }) {
            Win16WindowCallResult::Boolean(result) => result,
            result => panic!("unexpected native relationship result: {result:?}"),
        }
    }

    fn destroy(&self, window: Win16HostWindow) {
        assert!(matches!(self.call(Win16WindowCall::DestroyWindow {
            window: Win16WindowTarget::Mapped(window),
        }), Win16WindowCallResult::Destroyed { succeeded: true, .. }));
    }

    fn finish(mut self) {
        self.worker.shutdown().expect("retire all native query-test windows");
    }
}

#[test]
#[ignore = "requires a Windows USER desktop; creates hidden native window trees"]
fn child_point_queries_use_client_coordinates_immediate_children_and_z_order() {
    let host = NativeQueries::new();
    let parent = host.root();
    let child = host.window(Some(parent), [20, 30, 80, 60], WS_CHILD | WS_VISIBLE, 0);
    let grandchild = host.window(Some(child), [10, 10, 30, 30], WS_CHILD | WS_VISIBLE, 0);
    let parent_target = Win16WindowTarget::Mapped(parent);
    for flags in [None, Some(0)] {
        assert_eq!(host.hit(parent_target, [35, 45], flags), Some(child));
        assert_ne!(host.hit(parent_target, [35, 45], flags), Some(grandchild));
        assert_eq!(host.hit(parent_target, [200, 140], flags), Some(parent));
        for point in [[-1, 45], [240, 0], [0, 180], [-32768, 32767]] {
            assert_eq!(host.hit(parent_target, point, flags), None);
        }
    }
    let sibling = host.window(Some(parent), [20, 30, 80, 60], WS_CHILD | WS_VISIBLE, 0);
    host.top(sibling);
    for flags in [None, Some(0)] {
        assert_eq!(host.hit(parent_target, [35, 45], flags), Some(sibling));
        // Repeated results must retain the existing opaque identity.
        assert_eq!(host.hit(parent_target, [35, 45], flags), Some(sibling));
    }
    host.top(child);
    for flags in [None, Some(0)] {
        assert_eq!(host.hit(parent_target, [35, 45], flags), Some(child));
    }
    host.finish();
}

#[test]
#[ignore = "requires a Windows USER desktop; creates hidden native window trees"]
fn child_point_ex_filters_only_requested_child_styles() {
    let host = NativeQueries::new();
    for (style, ex_style, skipped_by) in [
        (WS_CHILD, 0, SKIP_INVISIBLE),
        (WS_CHILD | WS_VISIBLE | WS_DISABLED, 0, SKIP_DISABLED),
        (WS_CHILD | WS_VISIBLE, WS_EX_TRANSPARENT, SKIP_TRANSPARENT),
        (WS_CHILD | WS_DISABLED, WS_EX_TRANSPARENT,
            SKIP_INVISIBLE | SKIP_DISABLED | SKIP_TRANSPARENT),
    ] {
        let parent = host.root();
        let bottom = host.window(Some(parent), [20, 30, 80, 60], WS_CHILD | WS_VISIBLE, 0);
        let top = host.window(Some(parent), [20, 30, 80, 60], style, ex_style);
        host.top(top);
        let parent_target = Win16WindowTarget::Mapped(parent);
        assert_eq!(host.hit(parent_target, [35, 45], None), Some(top));
        for flags in 0..=7 {
            let expected = if flags & skipped_by == 0 { top } else { bottom };
            assert_eq!(host.hit(parent_target, [35, 45], Some(flags)), Some(expected),
                "style={style:#x}, ex_style={ex_style:#x}, flags={flags}");
        }
        host.destroy(bottom);
        assert_eq!(host.hit(parent_target, [35, 45], Some(skipped_by)), Some(parent));
    }
    host.finish();
}

#[test]
#[ignore = "requires a Windows USER desktop; creates hidden native window trees"]
fn is_child_distinguishes_descendants_from_self_siblings_and_owners() {
    let host = NativeQueries::new();
    let parent = host.root();
    let child = host.window(Some(parent), [20, 30, 80, 60], WS_CHILD | WS_VISIBLE, 0);
    let grandchild = host.window(Some(child), [10, 10, 30, 30], WS_CHILD | WS_VISIBLE, 0);
    let sibling = host.window(Some(parent), [120, 30, 80, 60], WS_CHILD | WS_VISIBLE, 0);
    let owned_popup = host.window(Some(parent), [400, 300, 80, 60], WS_POPUP, 0);
    let unrelated = host.root();
    for (ancestor, descendant) in [(parent, child), (parent, grandchild), (child, grandchild)] {
        assert!(host.is_child(Win16WindowTarget::Mapped(ancestor),
            Win16WindowTarget::Mapped(descendant)));
    }
    for (ancestor, descendant) in [
        (parent, parent), (child, parent), (child, sibling), (sibling, child),
        (parent, owned_popup), (owned_popup, parent), (unrelated, child),
    ] {
        assert!(!host.is_child(Win16WindowTarget::Mapped(ancestor),
            Win16WindowTarget::Mapped(descendant)));
    }
    host.finish();
}

#[test]
#[ignore = "requires a Windows USER desktop; creates hidden native window trees"]
fn child_queries_reject_null_invalid_unknown_and_retired_window_tokens() {
    let host = NativeQueries::new();
    let parent = host.root();
    let child = host.window(Some(parent), [20, 30, 80, 60], WS_CHILD | WS_VISIBLE, 0);
    host.destroy(child);
    let replacement = host.window(Some(parent), [20, 30, 80, 60], WS_CHILD | WS_VISIBLE, 0);
    assert_ne!(child, replacement);
    for target in [
        Win16WindowTarget::Null,
        Win16WindowTarget::Invalid,
        Win16WindowTarget::Mapped(Win16HostWindow(u64::MAX)),
        Win16WindowTarget::Mapped(child),
    ] {
        for flags in [None, Some(0), Some(7)] {
            assert_eq!(host.hit(target, [35, 45], flags), None);
        }
        for live in [parent, replacement] {
            assert!(!host.is_child(target, Win16WindowTarget::Mapped(live)));
            assert!(!host.is_child(Win16WindowTarget::Mapped(live), target));
        }
    }
    for flags in [None, Some(0)] {
        assert_eq!(host.hit(Win16WindowTarget::Mapped(parent), [35, 45], flags),
            Some(replacement));
    }
    host.destroy(parent);
    for token in [parent, replacement] {
        for flags in [None, Some(0)] {
            assert_eq!(host.hit(Win16WindowTarget::Mapped(token), [35, 45], flags), None);
        }
    }
    assert!(!host.is_child(Win16WindowTarget::Mapped(parent),
        Win16WindowTarget::Mapped(replacement)));
    host.finish();
}

#[test]
#[ignore = "requires a Windows USER desktop; creates hidden native window trees"]
fn destroy_receipts_include_callback_free_owned_popups_and_children() {
    let host = NativeQueries::new();
    let parent = host.root();
    let child = host.window(Some(parent), [10, 10, 40, 30], WS_CHILD, 0);
    let popup = host.window(Some(parent), [400, 300, 40, 30], WS_POPUP, 0);
    let survivor = host.root();
    // Ownership is a native destruction relationship, not a child-parent edge.
    assert!(!host.is_child(Win16WindowTarget::Mapped(parent),
        Win16WindowTarget::Mapped(popup)));
    let Win16WindowCallResult::Destroyed { succeeded, retirements } =
        host.call(Win16WindowCall::DestroyWindow {
            window: Win16WindowTarget::Mapped(parent),
        }) else { panic!("DestroyWindow must return exact retirement receipts"); };
    assert!(succeeded);
    let mut actual: Vec<_> = retirements.receipts.iter().map(|receipt| receipt.window).collect();
    actual.sort_unstable();
    let mut expected = vec![parent, child, popup];
    expected.sort_unstable();
    assert_eq!(actual, expected);
    for window in expected {
        assert!(matches!(host.call(Win16WindowCall::IsWindow {
            window: Win16WindowTarget::Mapped(window),
        }), Win16WindowCallResult::Boolean(false)));
    }
    assert!(matches!(host.call(Win16WindowCall::IsWindow {
        window: Win16WindowTarget::Mapped(survivor),
    }), Win16WindowCallResult::Boolean(true)));
    host.finish();
}

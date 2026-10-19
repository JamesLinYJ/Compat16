//! The native half of copied class-menu creation: actual HWND/HMENU readback.

use super::*;
use runtime::{Win16MenuTemplate, Win16MenuTemplateItem};
use windows_sys::Win32::UI::WindowsAndMessaging::{GetMenuItemID, WS_OVERLAPPEDWINDOW};

static MENUS: Mutex<Vec<(Win16HostWindow, usize, u32)>> = Mutex::new(Vec::new());

fn capture_menus(state: &Rc<RefCell<WorkerState>>) {
    let mut snapshot = Vec::new();
    for (&token, &hwnd) in &state.borrow().windows {
        // SAFETY: This query runs on the worker with its exact HWND map. The
        // native menu is observed synchronously and never passed to runtime.
        let menu = crate::windows::win32_safe::get_menu(hwnd);
        let id = if menu.is_null() {
            u32::MAX
        } else {
            unsafe { GetMenuItemID(menu, 0) }
        };
        snapshot.push((token, menu as usize, id));
    }
    *MENUS.lock().unwrap() = snapshot;
}

fn snapshot(host: &Fixture) -> Vec<(Win16HostWindow, usize, u32)> {
    let (response, steps) = mpsc::channel();
    host.worker
        .send(WorkerCommand::TestWindowData {
            run: capture_menus,
            response,
        })
        .unwrap_or_else(|_| panic!("read native class menus"));
    steps.recv_timeout(TIMEOUT).unwrap().unwrap();
    MENUS.lock().unwrap().clone()
}

fn data(template: Option<Win16MenuTemplate>) -> Win16HostCreationData {
    Win16HostCreationData {
        class: CLASS,
        guest_instance: 0,
        guest_class_name: Win16HostClassName::Name(b"ClassMenuTest".to_vec()),
        guest_menu: 0,
        class_menu_template: template,
        create_parameter: 0,
        creation_data: None,
        mdi_client: None,
        dialog_root: false,
        menu: None,
        title: None,
        style: WS_OVERLAPPEDWINDOW,
        ex_style: 0,
        x: 0,
        y: 0,
        width: 80,
        height: 50,
        parent: None,
        child_id: None,
    }
}

fn create(host: &Fixture, data: Win16HostCreationData) -> Win16HostWindow {
    let Win16WindowResult::Created(result) = host.complete(Win16WindowOperation::Create {
        creation: Win16CreationId(host.next()),
        data,
    }) else {
        panic!("expected native class-menu window");
    };
    result
        .live_window
        .expect("hidden class-menu window must be created")
}

#[test]
#[ignore = "requires native Windows USER; creates hidden windows without interactive input"]
fn class_menu_native_creation_owns_distinct_menu_instances_and_clear_preserves_existing_menus() {
    let host = Fixture::new();
    let mut template = Win16MenuTemplate {
        items: vec![Win16MenuTemplateItem::Command {
            flags: 0,
            id: 101,
            text: b"First".to_vec(),
        }],
    };
    let first = create(&host, data(Some(template.clone())));
    template.items[0] = Win16MenuTemplateItem::Command {
        flags: 0,
        id: 202,
        text: b"Changed".to_vec(),
    };
    let second = create(&host, data(Some(template)));
    let cleared = create(&host, data(None));
    let menus = snapshot(&host);
    let first_menu = menus.iter().find(|entry| entry.0 == first).unwrap();
    let second_menu = menus.iter().find(|entry| entry.0 == second).unwrap();
    let cleared_menu = menus.iter().find(|entry| entry.0 == cleared).unwrap();
    assert_ne!(first_menu.1, 0);
    assert_ne!(second_menu.1, 0);
    assert_ne!(first_menu.1, second_menu.1);
    assert_eq!(first_menu.2, 101);
    assert_eq!(second_menu.2, 202);
    assert_eq!(cleared_menu.1, 0);
    host.complete(Win16WindowOperation::Destroy { window: first });
    let menus = snapshot(&host);
    assert!(!menus.iter().any(|entry| entry.0 == first));
    let retained = menus.iter().find(|entry| entry.0 == second).unwrap();
    assert_eq!(retained.1, second_menu.1);
    assert_eq!(retained.2, 202);
}

//! The native half of class resource replacement: actual class-field readback.

use super::*;
use crate::windows::win16_gdi_objects::{NativeClassBackground, Win16Objects};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    GetClassLongPtrW, LoadCursorW, LoadIconW, GCLP_HBRBACKGROUND, GCLP_HCURSOR, GCLP_HICON,
    IDC_ARROW, IDI_APPLICATION,
};

/// One observed GCLP_* value per class field, in query order.
static CLASS_FIELDS: Mutex<Vec<(i32, usize)>> = Mutex::new(Vec::new());
static ORIGINAL_COOKIE: AtomicUsize = AtomicUsize::new(0);

fn corrupt_cookie(state: &Rc<RefCell<WorkerState>>) {
    let mut state = state.borrow_mut();
    let window = *state.windows.keys().next().unwrap();
    let binding = state.window_identity_cookies.get_mut(&window).unwrap();
    ORIGINAL_COOKIE.store(binding.value, Ordering::Release);
    binding.value = binding.value.wrapping_add(1);
}

fn restore_cookie(state: &Rc<RefCell<WorkerState>>) {
    let mut state = state.borrow_mut();
    let window = *state.windows.keys().next().unwrap();
    state.window_identity_cookies.get_mut(&window).unwrap().value =
        ORIGINAL_COOKIE.load(Ordering::Acquire);
}

fn run_on_worker(host: &Fixture, run: fn(&Rc<RefCell<WorkerState>>)) {
    let (response, steps) = mpsc::channel();
    host.worker.send(WorkerCommand::TestWindowData { run, response })
        .unwrap_or_else(|_| panic!("run class-resource identity probe"));
    steps.recv_timeout(TIMEOUT).unwrap().unwrap();
}

fn capture_class_fields(state: &Rc<RefCell<WorkerState>>) {
    let state = state.borrow();
    assert_eq!(state.windows.len(), 1);
    let hwnd = *state.windows.values().next().unwrap();
    let mut fields = Vec::new();
    for index in [GCLP_HICON, GCLP_HCURSOR, GCLP_HBRBACKGROUND] {
        // SAFETY: This query runs on the owning USER worker with its exact
        // HWND map. The native value is observed and never stored.
        fields.push((index, unsafe { GetClassLongPtrW(hwnd, index) }));
    }
    *CLASS_FIELDS.lock().unwrap() = fields;
}

fn fields(host: &Fixture) -> Vec<(i32, usize)> {
    let (response, steps) = mpsc::channel();
    host.worker
        .send(WorkerCommand::TestWindowData { run: capture_class_fields, response })
        .unwrap_or_else(|_| panic!("read native class fields"));
    steps.recv_timeout(TIMEOUT).unwrap().unwrap();
    CLASS_FIELDS.lock().unwrap().clone()
}

fn replace(
    host: &Fixture,
    class: Win16HostClass,
    window: Win16HostWindow,
    resource: NativeClassResource,
) -> bool {
    let (response, steps) = mpsc::channel();
    host.worker
        .send(WorkerCommand::ReplaceClassResource { class, window, resource, response })
        .unwrap_or_else(|_| panic!("replace native class resource"));
    steps.recv_timeout(TIMEOUT).unwrap().unwrap()
}

fn field(host: &Fixture, index: i32) -> usize {
    fields(host)
        .into_iter()
        .find(|(queried, _)| *queried == index)
        .expect("every GCLP_* field is observed")
        .1
}

fn unregister(host: &Fixture, class: Win16HostClass) -> bool {
    let (response, result) = mpsc::channel();
    host.worker.send(WorkerCommand::UnregisterClass { class, response })
        .unwrap_or_else(|_| panic!("unregister class-resource test class"));
    result.recv_timeout(TIMEOUT).unwrap()
}

#[test]
#[ignore = "requires native Windows USER and GDI; creates hidden windows without interactive input"]
fn class_resource_background_retirement_preserves_displaced_and_stock_brushes() {
    use runtime::Win16HostGdiCleanup;
    use windows_sys::Win32::Graphics::Gdi::{GetObjectType, OBJ_BRUSH};
    for use_stock in [false, true] {
        let host = Fixture::new();
        let mut objects = Win16Objects::new();
        let old = objects.create_solid_brush(0x112233).unwrap().unwrap();
        let current = objects.create_solid_brush(0x445566).unwrap().unwrap();
        let native_current = objects.native_brush(current).unwrap();
        assert!(replace(&host, CLASS, host.window,
            NativeClassResource::Background(objects.class_background(old).unwrap())));
        assert!(!unregister(&host, CLASS), "a live window prevents class unregistration");
        assert!(objects.native_brush(old).is_some(), "a failed unregister retires nothing");
        assert!(replace(&host, CLASS, host.window,
            NativeClassResource::Background(objects.class_background(current).unwrap())));
        assert!(objects.native_brush(old).is_some(), "replacement keeps the displaced brush live");
        let stock = objects.stock(0).unwrap().unwrap(); // WHITE_BRUSH
        if use_stock {
            assert!(replace(&host, CLASS, host.window,
                NativeClassResource::Background(objects.class_background(stock).unwrap())));
        }
        host.complete(Win16WindowOperation::Destroy { window: host.window });
        assert!(unregister(&host, CLASS));
        // SAFETY: GetObjectType checks the opaque GDI handle after USER's
        // acknowledged unregister; it never dereferences guest memory.
        if use_stock {
            assert_eq!(unsafe { GetObjectType(native_current) }, OBJ_BRUSH as u32);
            assert!(objects.native_brush(stock).is_some(), "stock brushes remain usable");
            assert!(objects.delete(current));
        } else {
            assert_eq!(unsafe { GetObjectType(native_current) }, 0,
                "USER deletes the then-current custom brush");
            assert_eq!(objects.cleanup_owned(current).unwrap(), Win16HostGdiCleanup::Absent,
                "the table must acknowledge retirement instead of attempting another delete");
        }
        assert!(objects.delete(old));

        // The initial RegisterClass path shares this ownership contract even
        // when no window of that registration was ever created.
        let initial = objects.create_solid_brush(0x778899).unwrap().unwrap();
        let class = Win16HostClass(0x4040);
        let (response, result) = mpsc::channel();
        host.worker.send(WorkerCommand::RegisterClass {
            class,
            spec: Win16HostClassSpec { style: 0, class_extra: 0, window_extra: 0,
                icon: None, cursor: None,
                background: Some(runtime::Win16ClassBackground::Brush(initial)),
                system_class: None },
            icon: 0, cursor: 0, background: objects.class_background(initial).unwrap(), response,
        }).unwrap_or_else(|_| panic!("register an initial class background"));
        assert!(result.recv_timeout(TIMEOUT).unwrap().unwrap().is_some());
        assert!(unregister(&host, class));
        assert_eq!(objects.cleanup_owned(initial).unwrap(), Win16HostGdiCleanup::Absent);
    }
}

#[test]
#[ignore = "requires native Windows USER; creates a hidden window without interactive input"]
fn class_resource_native_replacement_reaches_only_the_registered_class() {
    use windows_sys::Win32::Graphics::Gdi::{GetSysColorBrush, COLOR_WINDOW};
    let host = Fixture::new();
    assert_eq!(fields(&host), vec![(GCLP_HICON, 0), (GCLP_HCURSOR, 0), (GCLP_HBRBACKGROUND, 0)]);
    // SAFETY: GetSysColorBrush reads the host color table and returns an
    // OS-owned brush that needs no release.
    let brush = unsafe { GetSysColorBrush(COLOR_WINDOW as i32) } as usize;
    assert_ne!(brush, 0);
    assert!(replace(&host, CLASS, host.window, NativeClassResource::Background(NativeClassBackground::shared(brush))));
    // Shared system images are loaded without changing the visible cursor;
    // their lifetime is owned by USER, so no test destruction is needed.
    let icon = unsafe { LoadIconW(std::ptr::null_mut(), IDI_APPLICATION) } as usize;
    let cursor = unsafe { LoadCursorW(std::ptr::null_mut(), IDC_ARROW) } as usize;
    assert_ne!(icon, 0);
    assert_ne!(cursor, 0);
    let accepted = replace(&host, CLASS, host.window, NativeClassResource::Icon(icon));
    assert!(accepted, "native class fields after icon replacement: {:?}", fields(&host));
    assert!(replace(&host, CLASS, host.window, NativeClassResource::Cursor(cursor)));
    assert_eq!(fields(&host), vec![
        (GCLP_HICON, icon), (GCLP_HCURSOR, cursor), (GCLP_HBRBACKGROUND, brush),
    ]);
    assert!(replace(&host, CLASS, host.window, NativeClassResource::Icon(0)));
    assert_eq!(field(&host, GCLP_HICON), 0);
    assert_eq!(field(&host, GCLP_HCURSOR), cursor);
    assert!(replace(&host, CLASS, host.window, NativeClassResource::Cursor(0)));
    assert_eq!(field(&host, GCLP_HCURSOR), 0);
    assert_eq!(field(&host, GCLP_HBRBACKGROUND), brush);
    assert_eq!(field(&host, GCLP_HICON), 0, "one field does not disturb its neighbours");
    assert_eq!(field(&host, GCLP_HCURSOR), 0);
    // Clearing the field is a replacement of the same class field.
    assert!(replace(&host, CLASS, host.window, NativeClassResource::Background(NativeClassBackground::default())));
    assert_eq!(field(&host, GCLP_HBRBACKGROUND), 0);
    assert!(replace(&host, CLASS, host.window, NativeClassResource::Background(NativeClassBackground::shared(brush))));
    // Only the exact class/window pairing may redirect the native write.
    assert!(!replace(&host, Win16HostClass(0xdead), host.window,
        NativeClassResource::Background(NativeClassBackground::default())));
    assert_eq!(field(&host, GCLP_HBRBACKGROUND), brush, "a foreign class changed nothing");
    assert!(!replace(&host, CLASS, Win16HostWindow(0xdead), NativeClassResource::Background(NativeClassBackground::default())));
    assert_eq!(field(&host, GCLP_HBRBACKGROUND), brush, "a foreign window changed nothing");
    // Matching map entries alone do not establish the native incarnation.
    // Restore before asserting so shutdown can still destroy its owned HWND.
    run_on_worker(&host, corrupt_cookie);
    let accepted = replace(&host, CLASS, host.window, NativeClassResource::Background(NativeClassBackground::default()));
    run_on_worker(&host, restore_cookie);
    assert!(!accepted, "a mismatched native incarnation must not mutate the class");
    assert_eq!(field(&host, GCLP_HBRBACKGROUND), brush);
    // The class field is class-wide: the worker reports it regardless of which
    // member window the replacement was issued from, and the runtime-side
    // test covers the guest handle encoding.
    assert!(replace(&host, CLASS, host.window, NativeClassResource::Background(NativeClassBackground::default())));
    assert_eq!(field(&host, GCLP_HBRBACKGROUND), 0);
}

//! Native dialog entry and modeless completion retain exact root provenance.

use super::*;
use crate::win16_runtime::{
    test_support::{NoHost, tiny_ne_executable},
    windows::{WindowCallbackEntryPhase, WindowClassRoot, WindowReturn},
};
use crate::{
    Runtime, Win16HostCallback, Win16HostClass, Win16HostDialogMessage,
    Win16HostDialogResult, Win16HostWindowCreationResult, Win16HostWindowOperationId,
    Win16NativeCallbackSource, Win16NativeWindowApiReturn,
};

const ROOT: Win16HostClass = Win16HostClass(101);
const CHILD: Win16HostClass = Win16HostClass(202);

fn fixture() -> Runtime {
    Runtime::load(&tiny_ne_executable(), &[], br"C:\DIALOGCLASS.NE").unwrap()
}

fn creation(runtime: &Runtime, custom: bool, null_proc: bool) -> Win16UserFamilyContinuation {
    let state = runtime.win16.as_ref().unwrap();
    let instance = state.modules.records[&state.modules.main].instance;
    let mut class_routes = vec![GuestDialogClassRoute {
        root: false, control_id: Some(10), host_class: CHILD,
        guest_class_name: crate::Win16HostClassName::Name(b"CustomChild".to_vec()),
    }];
    if custom {
        class_routes.push(GuestDialogClassRoute {
            root: true, control_id: None, host_class: ROOT,
            guest_class_name: crate::Win16HostClassName::Name(b"CustomRoot".to_vec()),
        });
    }
    Win16UserFamilyContinuation {
        return_kind: Win16ReturnKind::Word,
        completion: FamilyCompletion::DialogCreate {
            creation: Win16CreationId(1),
            procedure: if null_proc { 0 } else { (u32::from(runtime.cpu.regs.cs) << 16) | 0x20 },
            instance, modal: false, class_routes,
            template_reference: Win16DialogTemplateRef::FarAddress { instance, template: 0 },
        },
        dialog_window: None, dialog_window_destroyed: false,
    }
}

fn expected_root(custom: bool) -> WindowClassRoot {
    if custom { WindowClassRoot::Class(ROOT) } else { WindowClassRoot::NoRegistration }
}

#[test]
fn callback_class_native_dialog_records_builtin_custom_and_null_procedure_roots() {
    for custom in [false, true] {
        for null_proc in [false, true] {
            for fail_setup in [false, true] {
                let mut runtime = fixture();
                let continuation = creation(&runtime, custom, null_proc);
                let state = runtime.win16.as_mut().unwrap();
                state.window_dispatch_context = Some(runtime.cpu.capture_context());
                state.push_window_operation(runtime.cpu.regs.clone(),
                    (runtime.cpu.regs.cs, 0x12, 0x80), WindowReturn::UserFamily(continuation)).unwrap();
                state.window_dispatch_context = None;
                if fail_setup { runtime.cpu.regs.set_sp(0); }
                let native = Win16HostWindow(500);
                let result = state.begin_dialog_callback(&mut runtime.cpu.regs, &mut runtime.memory,
                    &mut NoHost, Win16HostWindowOperationId(1), Win16HostCallback(2), native,
                    Win16HostDialogMessage::Init {
                        focus: None, focus_ancestry: Vec::new(), init_parameter: 0,
                    }, Win16NativeCallbackSource::WindowMessage {
                        window: native, class: custom.then_some(ROOT), message: 0x110,
                    });
                if fail_setup && !null_proc { assert!(result.is_err()); }
                else { assert_eq!(result.unwrap(), !null_proc); }
                let hwnd = state.window_handles.iter().find_map(|(&guest, &window)|
                    (window == native).then_some(guest)).unwrap();
                assert_eq!(state.window_class_root(hwnd), expected_root(custom));
                assert_eq!(state.window_host_class(hwnd), custom.then_some(ROOT));
                assert!(state.window_is_dialog(hwnd));
                if null_proc {
                    assert!(state.window_callbacks.is_empty());
                    assert_eq!(state.dialog_procedures[&hwnd].0, 0);
                } else {
                    let frame = state.window_callbacks.last().unwrap();
                    assert_eq!(frame.class_root, expected_root(custom));
                    if fail_setup { assert_eq!(frame.entry_phase, WindowCallbackEntryPhase::SetupFailed); }
                    state.retire_window_handle(hwnd).unwrap();
                    state.next_window_handle = hwnd;
                    assert_eq!(state.allocate_window_handle(Win16HostWindow(501)), Some(hwnd));
                    assert_eq!(state.window_class_root(hwnd), WindowClassRoot::Unresolved);
                    assert_eq!(state.window_callbacks.last().unwrap().class_root, expected_root(custom));
                }
            }
        }
    }
}

#[test]
fn callback_class_modeless_completion_uses_root_route_not_custom_child_or_dlgproc() {
    for custom in [false, true] {
        for null_proc in [false, true] {
            let mut runtime = fixture();
            let continuation = creation(&runtime, custom, null_proc);
            assert_eq!(continuation.pending_dialog_class_root(), expected_root(custom));
            assert!(continuation.retains_window_class(CHILD));
            let native = Win16HostWindow(600);
            let state = runtime.win16.as_mut().unwrap();
            let completion = state.finish_user_family_service(continuation,
                Win16HostUserServiceResult::Dialog(Win16HostDialogResult::Created {
                    creation: Win16HostWindowCreationResult {
                        native_api_return: Win16NativeWindowApiReturn::ReturnedWindow,
                        preflight_rejection: None, live_window: Some(native),
                    }, menu: None,
                }), &mut runtime.memory, &mut NoHost).unwrap();
            let (hwnd, procedure, instance) = completion.dialog_procedure.unwrap();
            assert_eq!(completion.value, u32::from(hwnd));
            assert_eq!(state.window_class_root(hwnd), expected_root(custom));
            assert_eq!(state.window_host_class(hwnd), custom.then_some(ROOT));
            assert_ne!(state.window_host_class(hwnd), Some(CHILD));
            assert!(state.window_is_dialog(hwnd));
            assert_eq!(procedure == 0, null_proc);
            // Complete the same procedure-table publication as USER completion,
            // then enter guest-only dispatch after subclassing the DLGPROC.
            state.dialog_procedures.insert(hwnd,
                ((u32::from(runtime.cpu.regs.cs) << 16) | 0x22, instance));
            state.window_dispatch_context = Some(runtime.cpu.capture_context());
            let return_to = (runtime.cpu.regs.cs, 0x12, 0x80);
            state.begin_guest_dispatch_callback(&mut runtime.cpu.regs, &mut runtime.memory,
                win16_abi::Msg16 { hwnd, message: 0x100, ..win16_abi::Msg16::default() },
                false, return_to).unwrap();
            state.window_dispatch_context = None;
            let frame = state.window_callbacks.last().unwrap();
            assert_eq!(frame.class_root, expected_root(custom));
            assert_eq!(frame.native_source, None);
        }
    }
}

#[test]
fn callback_class_window_data_rejects_conflicting_or_reused_native_provenance() {
    let mut runtime = fixture();
    let state = runtime.win16.as_mut().unwrap();
    let native = Win16HostWindow(700);
    let hwnd = state.allocate_window_handle(native).unwrap();
    state.initialize_dialog_window_data(hwnd, 0).unwrap();
    assert_eq!(state.window_class_root(hwnd), WindowClassRoot::Unresolved);
    state.record_window_class_root(hwnd, native, WindowClassRoot::NoRegistration).unwrap();
    assert_eq!(state.window_host_class(hwnd), None);
    assert!(state.record_window_class_root(hwnd, native, WindowClassRoot::Class(ROOT)).is_err());
    assert_eq!(state.window_class_root(hwnd), WindowClassRoot::NoRegistration);
    state.window_handles.insert(hwnd, Win16HostWindow(701));
    assert_eq!(state.window_class_root(hwnd), WindowClassRoot::Unresolved);
    assert!(state.record_window_class_root(hwnd, native, WindowClassRoot::NoRegistration).is_err());
    assert!(state.initialize_dialog_window_data(hwnd, 0).is_err());
}

#[test]
fn callback_class_conflicting_native_dialog_source_retains_unresolved_owner_on_failure() {
    for claimed in [None, Some(CHILD)] {
        let mut runtime = fixture();
        let native = Win16HostWindow(800);
        let state = runtime.win16.as_mut().unwrap();
        let hwnd = state.allocate_window_handle(native).unwrap();
        state.initialize_window_data(hwnd, Some(ROOT), 0, true, Some(30)).unwrap();
        state.dialog_procedures.insert(hwnd, ((u32::from(runtime.cpu.regs.cs) << 16) | 0x20, 0));
        let source = Win16NativeCallbackSource::WindowMessage {
            window: native, class: claimed, message: 0x100,
        };
        assert!(state.begin_dialog_callback(&mut runtime.cpu.regs, &mut runtime.memory,
            &mut NoHost, Win16HostWindowOperationId(1), Win16HostCallback(2), native,
            Win16HostDialogMessage::Message(crate::Win16HostMessage::Scalar {
                kind: crate::Win16ScalarMessage::KeyDown, w_param: 0, l_param: 0,
            }), source).is_err());
        let frame = state.window_callbacks.last().unwrap();
        assert_eq!(frame.class_root, WindowClassRoot::Unresolved);
        assert_eq!(frame.entry_phase, WindowCallbackEntryPhase::SetupFailed);
        assert_eq!(frame.native_source, Some(source), "cancellation evidence must remain unchanged");
        state.retire_window_handle(hwnd).unwrap();
        assert_eq!(state.window_callbacks.last().unwrap().class_root, WindowClassRoot::Unresolved);
    }
}

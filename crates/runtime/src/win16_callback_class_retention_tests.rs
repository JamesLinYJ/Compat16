//! Callback class roots outlive HWND mappings without conflating code ownership.

use super::*;
use crate::win16_runtime::{
    message_calls::Win16TimerRegistration,
    windows::{WindowCallbackContinuation, WindowCallbackEntryPhase, WindowClassRoot},
};
use crate::{
    Win16HostCallback, Win16HostMessage, Win16HostWindowOperationId,
    Win16NativeCallbackSource, Win16ScalarMessage,
};
use win16_abi::Msg16;

// Run the same ownership cases through explicit removal and module retirement.
fn release(
    runtime: &mut Runtime, host: &mut ClassDataHost, module: bool,
    expected: &[(Registered, bool)],
) {
    let state = runtime.win16.as_mut().unwrap();
    if module {
        state.release_module_classes(&[state.modules.main], host).unwrap();
    } else {
        for &(class, retained) in expected {
            let result = state.unregister_class(class.info.h_instance,
                Win16ClassName::Atom(class.atom), host).unwrap();
            assert_eq!(result, u16::from(!retained));
        }
    }
    for &(class, retained) in expected {
        assert_eq!(state.is_registered_class_atom(class.atom), retained);
        assert_eq!(host.unregistrations.contains(&class.class), !retained);
    }
}

fn dispatch(runtime: &mut Runtime, hwnd: u16, timer: Option<u32>) {
    let return_to = (runtime.cpu.regs.cs, 0x12, u32::from(runtime.cpu.regs.sp()));
    let state = runtime.win16.as_mut().unwrap();
    state.window_dispatch_context = Some(runtime.cpu.capture_context());
    state.begin_guest_dispatch_callback(&mut runtime.cpu.regs, &mut runtime.memory,
        Msg16 { hwnd, message: if timer.is_some() { 0x113 } else { 0x100 },
            w_param: 7, l_param: timer.unwrap_or(9), time: 11, ..Msg16::default() },
        timer.is_some(), return_to).unwrap();
    state.window_dispatch_context = None;
}

fn call_procedure(runtime: &mut Runtime, host: &mut ClassDataHost,
    procedure: u32, hwnd: u16, w_param: u16,
) {
    let return_to = (runtime.cpu.regs.cs, 0x12, u32::from(runtime.cpu.regs.sp()));
    let state = runtime.win16.as_mut().unwrap();
    state.window_dispatch_context = Some(runtime.cpu.capture_context());
    state.begin_call_window_proc(&mut runtime.cpu.regs, &mut runtime.memory, host,
        procedure, hwnd, 0x100, w_param, 9, return_to).unwrap();
    state.window_dispatch_context = None;
}

fn return_callback(runtime: &mut Runtime, host: &mut ClassDataHost, value: u32)
    -> Result<(), RuntimeError>
{
    let state = runtime.win16.as_mut().unwrap();
    let saved = &state.window_callbacks.last().unwrap().saved;
    runtime.cpu.regs.ss = saved.ss;
    runtime.cpu.regs.set_sp(saved.sp());
    runtime.cpu.regs.set_ip(0);
    runtime.cpu.regs.set_ax(value as u16);
    runtime.cpu.regs.set_dx((value >> 16) as u16);
    state.finish_window_callback(&mut runtime.cpu.regs, &mut runtime.memory, host)
}

fn enter_native(runtime: &mut Runtime, host: &mut ClassDataHost, hwnd: u16,
    class: Registered, message: Win16HostMessage, message_id: u32,
) -> Result<(), RuntimeError> {
    let state = runtime.win16.as_mut().unwrap();
    let native = state.window_handles[&hwnd];
    let procedure = state.window_procedures[&hwnd];
    state.begin_host_window_callback(&mut runtime.cpu.regs, &mut runtime.memory, host,
        Win16HostWindowOperationId(1), Win16HostCallback(2), native, hwnd, procedure,
        message, None, Win16NativeCallbackSource::WindowMessage {
            window: native, class: Some(class.class), message: message_id,
        }, false)
}

fn enter_timer(runtime: &mut Runtime, native: Option<Win16HostWindow>, host_id: Option<u64>,
    guest_l_param: u32,
) -> Result<bool, RuntimeError> {
    let source = Win16NativeCallbackSource::Timer {
        window: native, host_timer_id: host_id, guest_w_param: 7, guest_l_param, time: 11,
    };
    runtime.win16.as_mut().unwrap().begin_host_timer_callback(
        &mut runtime.cpu.regs, &mut runtime.memory, &mut ClassDataHost::default(),
        Win16HostCallback(2), native,
        host_id, 7, guest_l_param, 11, Win16HostWindowOperationId(1), source)
}

#[test]
fn callback_class_guest_dispatch_retains_snapshot_after_hwnd_retirement_and_reuse() {
    for module in [false, true] {
        for dialog in [false, true] {
            let mut runtime = fixture();
            let mut host = ClassDataHost::default();
            let original = named_class(&mut runtime, &mut host, b"Original", 0);
            let replacement = named_class(&mut runtime, &mut host, b"Replacement", 0);
            let unrelated = named_class(&mut runtime, &mut host, b"SharedFar", 0);
            assert_eq!(original.info.lpfn_wnd_proc, unrelated.info.lpfn_wnd_proc);
            let hwnd = window(&mut runtime, original, 1);
            if dialog {
                runtime.win16.as_mut().unwrap().dialog_procedures.insert(hwnd,
                    (original.info.lpfn_wnd_proc, original.info.h_instance));
            }
            dispatch(&mut runtime, hwnd, None);
            let state = runtime.win16.as_mut().unwrap();
            let frame = state.window_callbacks.last().unwrap();
            assert_eq!(frame.class_root, WindowClassRoot::Class(original.class));
            assert_eq!(frame.native_source, None, "guest entry must not invent native ownership");
            state.retire_window_handle(hwnd).unwrap();
            state.next_window_handle = hwnd;
            assert_eq!(window(&mut runtime, replacement, 2), hwnd);
            runtime.win16.as_mut().unwrap().retire_window_handle(hwnd).unwrap();
            release(&mut runtime, &mut host, module,
                &[(original, true), (replacement, false), (unrelated, false)]);
            return_callback(&mut runtime, &mut host, 0).unwrap();
            assert!(runtime.win16.as_ref().unwrap().window_callbacks.is_empty());
            release(&mut runtime, &mut host, module, &[(original, false)]);
        }
    }
}

#[test]
fn callback_class_subclass_dispatch_retains_registration_but_arbitrary_far_call_does_not() {
    for module in [false, true] {
        for wndproc_dispatch in [false, true] {
            let mut runtime = fixture();
            let mut host = ClassDataHost::default();
            let original = named_class(&mut runtime, &mut host, b"Subclassed", 0);
            let mut other_info = class_info(&runtime, 0);
            other_info.lpfn_wnd_proc += 2;
            let target = register(&mut runtime, &mut host, other_info,
                Win16ClassName::Name(b"TargetProcedure".to_vec()));
            let hwnd = window(&mut runtime, original, 1);
            assert_eq!(call(&mut runtime, &mut host, 136, hwnd, -4,
                Some(target.info.lpfn_wnd_proc)), original.info.lpfn_wnd_proc);
            if wndproc_dispatch { dispatch(&mut runtime, hwnd, None); }
            else { call_procedure(&mut runtime, &mut host, target.info.lpfn_wnd_proc, hwnd, 7); }
            let state = runtime.win16.as_mut().unwrap();
            let frame = state.window_callbacks.last().unwrap();
            assert_eq!(frame.callback_address, target.info.lpfn_wnd_proc);
            assert_eq!(frame.class_root, if wndproc_dispatch { WindowClassRoot::Class(original.class) }
                else { WindowClassRoot::NoRegistration });
            assert_eq!(frame.native_source, None);
            if !wndproc_dispatch {
                assert!(matches!(frame.continuation,
                    WindowCallbackContinuation::GuestProcedureCall { forwarded: None }));
            }
            state.retire_window_handle(hwnd).unwrap();
            release(&mut runtime, &mut host, module, &[(original, wndproc_dispatch), (target, false)]);
            return_callback(&mut runtime, &mut host, 0).unwrap();
            if wndproc_dispatch { release(&mut runtime, &mut host, module, &[(original, false)]); }
        }
    }
}

#[test]
fn callback_class_true_timerproc_is_class_free_but_window_fallback_retains_class() {
    for module in [false, true] {
        // Both a registered TIMERPROC and a verified guest-post sidecar are
        // class-free, even when their FAR address equals a registered WndProc.
        for route in 0..5 {
            let mut runtime = fixture();
            let mut host = ClassDataHost::default();
            let class = named_class(&mut runtime, &mut host, b"TimerClass", 0);
            let unrelated = named_class(&mut runtime, &mut host, b"TimerOther", 0);
            let hwnd = window(&mut runtime, class, 1);
            let native = runtime.win16.as_ref().unwrap().window_handles[&hwnd];
            let fallback = route >= 3;
            if route == 4 {
                runtime.win16.as_mut().unwrap().dialog_procedures.insert(hwnd,
                    (class.info.lpfn_wnd_proc, class.info.h_instance));
            }
            if route == 0 {
                dispatch(&mut runtime, hwnd, Some(class.info.lpfn_wnd_proc));
            } else {
                let registered = route == 1 || route == 3;
                if registered {
                    runtime.win16.as_mut().unwrap().timers.insert(hwnd, 7,
                        Win16TimerRegistration { host_id: 41, host_window: Some(native),
                            callback: (!fallback).then_some(class.info.lpfn_wnd_proc) });
                }
                if route == 1 {
                    let state = runtime.win16.as_mut().unwrap();
                    state.retire_window_handle(hwnd).unwrap();
                    state.next_window_handle = hwnd;
                    assert_eq!(window(&mut runtime, unrelated, 2), hwnd);
                }
                assert!(enter_timer(&mut runtime, Some(native), registered.then_some(41),
                    if fallback || registered { 0 } else { class.info.lpfn_wnd_proc }).unwrap());
            }
            let state = runtime.win16.as_mut().unwrap();
            assert_eq!(state.window_callbacks.last().unwrap().class_root,
                if fallback { WindowClassRoot::Class(class.class) }
                else { WindowClassRoot::NoRegistration });
            if route == 0 { assert_eq!(state.window_callbacks.last().unwrap().native_source, None); }
            state.retire_window_handle(hwnd).unwrap();
            release(&mut runtime, &mut host, module, &[(class, fallback), (unrelated, false)]);
        }
    }
}

#[test]
fn callback_class_stale_timer_fallback_cannot_enter_reused_hwnd_procedure() {
    for module in [false, true] {
        let mut runtime = fixture();
        let mut host = ClassDataHost::default();
        let old = named_class(&mut runtime, &mut host, b"OldTimer", 0);
        let replacement = named_class(&mut runtime, &mut host, b"NewTimer", 0);
        let hwnd = window(&mut runtime, old, 1);
        let state = runtime.win16.as_mut().unwrap();
        let old_native = state.window_handles[&hwnd];
        state.timers.insert(hwnd, 7, Win16TimerRegistration {
            host_id: 41, host_window: Some(old_native), callback: None,
        });
        state.retire_window_handle(hwnd).unwrap();
        state.next_window_handle = hwnd;
        assert_eq!(window(&mut runtime, replacement, 2), hwnd);
        let state = runtime.win16.as_mut().unwrap();
        let new_native = state.window_handles[&hwnd];
        state.timers.insert(hwnd, 7, Win16TimerRegistration {
            host_id: 42, host_window: Some(new_native), callback: None,
        });
        let saved = (runtime.cpu.regs.cs, runtime.cpu.regs.ip(), runtime.cpu.regs.sp());
        assert!(!enter_timer(&mut runtime, Some(old_native), Some(41), 0).unwrap());
        assert!(!enter_timer(&mut runtime, Some(new_native), Some(41), 0).unwrap());
        assert!(!enter_timer(&mut runtime, Some(old_native), None, 0).unwrap());
        assert_eq!((runtime.cpu.regs.cs, runtime.cpu.regs.ip(), runtime.cpu.regs.sp()), saved);
        assert!(runtime.win16.as_ref().unwrap().window_callbacks.is_empty());
        runtime.win16.as_mut().unwrap().retire_window_handle(hwnd).unwrap();
        release(&mut runtime, &mut host, module, &[(old, false), (replacement, false)]);
    }
}

#[test]
fn callback_class_native_frame_survives_setup_payload_and_resume_failures() {
    for module in [false, true] {
        for failure in 0..3 {
            let mut runtime = fixture();
            let mut host = ClassDataHost::default();
            let class = named_class(&mut runtime, &mut host, b"NativeOwner", 0);
            let unrelated = named_class(&mut runtime, &mut host, b"SameNativeFar", 0);
            let hwnd = window(&mut runtime, class, 1);
            if failure == 0 { runtime.cpu.regs.set_sp(0); }
            let message = if failure == 1 {
                Win16HostMessage::GetText { capacity: 4, buffer_is_null: false }
            } else {
                Win16HostMessage::Scalar { kind: Win16ScalarMessage::KeyDown,
                    w_param: 7, l_param: 9 }
            };
            let entered = enter_native(&mut runtime, &mut host, hwnd, class,
                message, if failure == 1 { 0xd } else { 0x100 });
            if failure == 0 {
                assert!(entered.is_err());
                let frame = runtime.win16.as_ref().unwrap().window_callbacks.last().unwrap();
                assert_eq!(frame.entry_phase, WindowCallbackEntryPhase::SetupFailed);
                assert!(frame.setup_error.is_some());
            } else {
                entered.unwrap();
                if failure == 1 {
                    let state = runtime.win16.as_mut().unwrap();
                    let allocation = state.window_callbacks.last().unwrap().payload.allocation.unwrap();
                    state.heap.page_lock(allocation).unwrap();
                }
                // Invalid WM_GETTEXT output leaves its pinned payload in the
                // callback. The scalar route reaches the host's resume error.
                assert!(return_callback(&mut runtime, &mut host, 8).is_err());
                let frame = runtime.win16.as_ref().unwrap().window_callbacks.last().unwrap();
                if failure == 1 {
                    assert!(frame.payload_error.is_some());
                    assert!(frame.payload_retained.is_some());
                    assert!(!frame.payload_cleaned);
                } else {
                    assert!(frame.payload_cleaned);
                    assert!(frame.native_resume_error.is_some());
                    // A failed native resume is remembered, not retried as a
                    // new callback or mistaken for a successful return.
                    assert!(return_callback(&mut runtime, &mut host, 0).is_err());
                }
            }
            let state = runtime.win16.as_mut().unwrap();
            assert_eq!(state.window_callbacks.last().unwrap().class_root,
                WindowClassRoot::Class(class.class));
            state.retire_window_handle(hwnd).unwrap();
            state.next_window_handle = hwnd;
            assert_eq!(window(&mut runtime, unrelated, 2), hwnd);
            runtime.win16.as_mut().unwrap().retire_window_handle(hwnd).unwrap();
            release(&mut runtime, &mut host, module, &[(class, true), (unrelated, false)]);
        }
    }
}

#[test]
fn callback_class_forwarding_uses_only_exact_innermost_native_capability() {
    let mut runtime = fixture();
    let mut host = ClassDataHost::default();
    let class = named_class(&mut runtime, &mut host, b"Forwarded", 0);
    let other = named_class(&mut runtime, &mut host, b"Nested", 0);
    let hwnd = window(&mut runtime, class, 1);
    let nested = window(&mut runtime, other, 2);
    enter_native(&mut runtime, &mut host, hwnd, class,
        Win16HostMessage::Scalar { kind: Win16ScalarMessage::KeyDown,
            w_param: 7, l_param: 9 }, 0x100).unwrap();
    call_procedure(&mut runtime, &mut host, class.info.lpfn_wnd_proc, hwnd, 7);
    let frame = runtime.win16.as_ref().unwrap().window_callbacks.last().unwrap();
    let WindowCallbackContinuation::GuestProcedureCall { forwarded: Some(source) }
        = frame.continuation else { panic!("exact message lost forwarding capability") };
    assert_eq!(source.callback, Win16HostCallback(2));
    assert_eq!(source.class_root, WindowClassRoot::Class(class.class));
    assert_eq!(frame.class_root, source.class_root);
    assert_eq!(frame.native_source, None);
    // A mismatched tuple must not copy a suspended native capability.
    call_procedure(&mut runtime, &mut host, class.info.lpfn_wnd_proc, hwnd, 8);
    assert!(matches!(runtime.win16.as_ref().unwrap().window_callbacks.last().unwrap().continuation,
        WindowCallbackContinuation::GuestProcedureCall { forwarded: None }));
    // An intervening guest dispatch blocks search through older frames even
    // when a later CallWindowProc supplies the original tuple again.
    dispatch(&mut runtime, nested, None);
    call_procedure(&mut runtime, &mut host, class.info.lpfn_wnd_proc, hwnd, 7);
    let state = runtime.win16.as_ref().unwrap();
    let frame = state.window_callbacks.last().unwrap();
    assert!(matches!(frame.continuation,
        WindowCallbackContinuation::GuestProcedureCall { forwarded: None }));
    assert_eq!(frame.class_root, WindowClassRoot::NoRegistration);
    assert_eq!(frame.native_source, None);
}

#[test]
fn callback_class_unknown_provenance_is_conservative_and_builtin_proof_is_explicit() {
    for module in [false, true] {
        let mut runtime = fixture();
        let mut host = ClassDataHost::default();
        let class = named_class(&mut runtime, &mut host, b"UnknownOwner", 0);
        let native = Win16HostWindow(0xfedc_0000_0010);
        let state = runtime.win16.as_mut().unwrap();
        let hwnd = state.allocate_window_handle(native).unwrap();
        state.initialize_window_data(hwnd, None, class.info.h_instance, true, Some(30)).unwrap();
        state.dialog_procedures.insert(hwnd, (class.info.lpfn_wnd_proc, class.info.h_instance));
        assert_eq!(state.window_class_root(hwnd), WindowClassRoot::Unresolved);
        dispatch(&mut runtime, hwnd, None);
        assert_eq!(runtime.win16.as_ref().unwrap().window_callbacks.last().unwrap().class_root,
            WindowClassRoot::Unresolved);
        release(&mut runtime, &mut host, module, &[(class, true)]);
        if !module { assert!(host.diagnostics.contains(&Kind::CompatibilityGap)); }
        return_callback(&mut runtime, &mut host, 0).unwrap();
        let state = runtime.win16.as_mut().unwrap();
        assert!(state.record_window_class_root(hwnd, Win16HostWindow(native.0 + 1),
            WindowClassRoot::NoRegistration).is_err());
        assert_eq!(state.window_class_root(hwnd), WindowClassRoot::Unresolved);
        state.record_window_class_root(hwnd, native, WindowClassRoot::NoRegistration).unwrap();
        assert_eq!(state.window_class_root(hwnd), WindowClassRoot::NoRegistration);
        dispatch(&mut runtime, hwnd, None);
        let frame = runtime.win16.as_ref().unwrap().window_callbacks.last().unwrap();
        assert_eq!(frame.class_root, WindowClassRoot::NoRegistration);
        assert_eq!(frame.native_source, None);
        release(&mut runtime, &mut host, module, &[(class, false)]);
    }
}

#[test]
fn callback_class_pending_window_and_mdi_creation_block_both_release_routes() {
    use crate::win16_runtime::{
        guest_ranges::GuestOutputRange, messages::MessageOutput,
        messages_mdi::{MdiCreateOutputPlan, MdiOutputPlan},
        user_services_controls::{FamilyCompletion, Win16UserFamilyContinuation},
        windows::{WindowCreateRequest, WindowReturn},
    };
    for module in [false, true] {
        for route in 0..4 {
            let mut runtime = fixture();
            let mut host = ClassDataHost::default();
            let class = named_class(&mut runtime, &mut host, b"PendingCreation", 0);
            let other = named_class(&mut runtime, &mut host, b"NotCreating", 0);
            let state = runtime.win16.as_mut().unwrap();
            let continuation = if route == 0 {
                WindowReturn::Create { creation: crate::Win16CreationId(1),
                    request: WindowCreateRequest {
                        class_name: Win16ClassName::Atom(class.atom), window_name: None,
                        ex_style: 0, style: 0, x: 0, y: 0, width: 1, height: 1,
                        parent: 0, menu: 0, instance: class.info.h_instance, parameter: 0,
                    },
                    procedure: WindowProcedure { class: class.class,
                        address: class.info.lpfn_wnd_proc, instance: class.info.h_instance },
                    window: None, parent_was_updated: false,
                }
            } else {
                let pointer = state.selectors.pointer_from_raw(Selector(runtime.cpu.regs.ds), 0x60).unwrap();
                let plan = MdiCreateOutputPlan {
                    range: GuestOutputRange::capture(state, &runtime.memory, pointer, 18).unwrap(),
                    owner_instance: class.info.h_instance, creation: crate::Win16CreationId(1),
                    mdi: crate::Win16HostMdiCreate {
                        creation: crate::Win16CreationId(1), class: class.class,
                        guest_class_name: crate::Win16HostClassName::Atom(class.atom),
                        owner_instance: class.info.h_instance, title: None,
                        x: 0, y: 0, cx: 10, cy: 10, style: 0, parameter: 0,
                    },
                    child_procedure: class.info.lpfn_wnd_proc, child_instance: class.info.h_instance,
                    system_kind: None, mdi_client_guest: 2, mdi_client_native: Win16HostWindow(1),
                };
                match route {
                    1 => WindowReturn::Message { output: MessageOutput::Mdi(Some(MdiOutputPlan::Create(plan))) },
                    2 => WindowReturn::DispatchMessage { mdi_output: Some(MdiOutputPlan::Create(plan)) },
                    _ => WindowReturn::UserFamily(Win16UserFamilyContinuation {
                        return_kind: Win16ReturnKind::Dword,
                        completion: FamilyCompletion::DialogDefaultProcedure {
                            output: MessageOutput::Mdi(Some(MdiOutputPlan::Create(plan))),
                        }, dialog_window: None, dialog_window_destroyed: false,
                    }),
                }
            };
            state.window_dispatch_context = Some(runtime.cpu.capture_context());
            state.push_window_operation(runtime.cpu.regs.clone(),
                (runtime.cpu.regs.cs, 0x12, u32::from(runtime.cpu.regs.sp())), continuation).unwrap();
            state.window_dispatch_context = None;
            assert!(state.window_handles.is_empty());
            release(&mut runtime, &mut host, module, &[(class, true), (other, false)]);
            runtime.win16.as_mut().unwrap().window_operations.pop();
            release(&mut runtime, &mut host, module, &[(class, false)]);
        }
    }
}

#[test]
fn callback_class_free_library_and_reaping_keep_callback_owned_registration() {
    use crate::win16_runtime::{module_memory::ModuleAllocation, module_registry::ModuleState};
    let mut runtime = fixture();
    let mut host = ClassDataHost::default();
    let mut donor = fixture();
    let donor_state = donor.win16.as_mut().unwrap();
    let mut module = donor_state.modules.records.remove(&donor_state.modules.main).unwrap();
    let state = runtime.win16.as_mut().unwrap();
    // Real module retirement cancels selector-generation-bound notifications
    // and frees its private header. A fabricated numeric handle cannot satisfy
    // that contract even when the module intentionally owns no executable code.
    let header = ModuleAllocation::allocate(&mut state.heap, &mut state.selectors,
        &mut runtime.memory, 64, false).unwrap();
    let header_selector = header.selector;
    let header_global = header.handle;
    let module_handle = header_selector.raw().0;
    module.handle = module_handle;
    module.instance = module_handle;
    module.loaded = None;
    module.definition = None;
    module.allocations = vec![header];
    module.deps.clear();
    module.pinned = false;
    module.explicit_refs = 1;
    module.continuation_owner_refs = 0;
    assert!(state.modules.records.insert(module_handle, module).is_none());
    let mut info = class_info(&runtime, 0);
    info.h_instance = module_handle;
    let class = register(&mut runtime, &mut host, info, Win16ClassName::Name(b"DllClass".to_vec()));
    let hwnd = window(&mut runtime, class, 1);
    dispatch(&mut runtime, hwnd, None);
    let return_to = (runtime.cpu.regs.cs, 0x22, u32::from(runtime.cpu.regs.sp()));
    let state = runtime.win16.as_mut().unwrap();
    state.retire_window_handle(hwnd).unwrap();
    state.begin_free_library(module_handle, &mut runtime.cpu.regs, &mut runtime.memory,
        &mut host, return_to).unwrap();
    assert_eq!(state.modules.records[&module_handle].explicit_refs, 0);
    assert_eq!(state.modules.records[&module_handle].state, ModuleState::Ready);
    assert!(state.is_registered_class_atom(class.atom));
    assert!(host.unregistrations.is_empty());
    state.module_reap_pending = true;
    state.reap_modules(&mut runtime.cpu, &mut runtime.memory, &mut host).unwrap();
    assert_eq!(state.modules.records[&module_handle].state, ModuleState::Ready);
    assert!(state.is_registered_class_atom(class.atom));
    assert!(state.selectors.describe(header_selector).is_ok());
    assert!(state.heap.info(header_global).is_ok());
    assert!(host.unregistrations.is_empty());
    return_callback(&mut runtime, &mut host, 0).unwrap();
    let state = runtime.win16.as_mut().unwrap();
    state.module_reap_pending = true;
    state.reap_modules(&mut runtime.cpu, &mut runtime.memory, &mut host).unwrap();
    assert!(!state.is_registered_class_atom(class.atom));
    assert!(!state.modules.records.contains_key(&module_handle));
    assert!(state.selectors.describe(header_selector).is_err());
    assert!(state.heap.info(header_global).is_err());
    assert_eq!(host.unregistrations, vec![class.class]);
}

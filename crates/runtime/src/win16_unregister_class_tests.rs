//! Real USER.403 service-gate dispatch, registry ownership and lifetime checks.

use super::*;
use crate::win16_runtime::{
    module_registry::ModuleState,
    windows::{WindowCallbackContinuation, WindowCallbackFrame, WindowClassRoot, WindowCreateRequest, WindowReturn},
};

fn unregister(
    runtime: &mut Runtime, host: &mut ClassDataHost, owner: u16, name: Win16ClassName,
) -> Result<u16, RuntimeError> {
    let descriptor = lookup_export(b"USER", ExportLookupTarget::Ordinal(403)).unwrap();
    let return_cs = runtime.cpu.regs.cs;
    let stack = runtime.cpu.regs.sp();
    let state = runtime.win16.as_mut().unwrap();
    let name_far = match name {
        Win16ClassName::Atom(atom) => u32::from(atom),
        Win16ClassName::Name(mut name) => {
            name.push(0);
            let pointer = state.selectors.pointer_from_raw(Selector(runtime.cpu.regs.ds), 0).unwrap();
            state.selectors.write(&mut runtime.memory, pointer, &name).unwrap();
            u32::from(runtime.cpu.regs.ds) << 16
        }
    };
    // Independently encode the physical Pascal frame, hInstance nearest return.
    let mut bytes = vec![0x12, 0];
    bytes.extend_from_slice(&return_cs.to_le_bytes());
    bytes.extend_from_slice(&owner.to_le_bytes());
    bytes.extend_from_slice(&name_far.to_le_bytes());
    let pointer = state.selectors.pointer_from_raw(Selector(runtime.cpu.regs.ss), stack).unwrap();
    state.selectors.write(&mut runtime.memory, pointer, &bytes).unwrap();
    let slot = state.bindings.len();
    state.bindings.push(ImportBinding::Supported(descriptor));
    runtime.cpu.regs.cs = state.gate_selector.0;
    runtime.cpu.regs.set_ip((slot * 2) as u16);
    runtime.cpu.regs.set_ax(0xa55a);
    runtime.cpu.regs.set_dx(0x5aa5);
    let result = state.dispatch(&mut runtime.cpu, &mut runtime.memory, &mut runtime.dos, host, 0)?;
    assert_eq!(result, None);
    assert_eq!((runtime.cpu.regs.cs, runtime.cpu.regs.ip(), runtime.cpu.regs.sp()),
        (return_cs, 0x12, stack + 10));
    assert_eq!(runtime.cpu.regs.dx(), 0x5aa5, "BOOL16 preserves DX");
    runtime.cpu.regs.set_sp(stack);
    Ok(runtime.cpu.regs.ax())
}

fn atom(class: Registered) -> Win16ClassName { Win16ClassName::Atom(class.atom) }
fn name(bytes: &[u8]) -> Win16ClassName { Win16ClassName::Name(bytes.to_vec()) }

#[test]
fn unregister_class_live_window_and_host_failures_preserve_state_until_success() {
    for failure in [HostResult::Refused, HostResult::Error] {
        let mut runtime = fixture();
        let mut host = ClassDataHost::default();
        let class = named_class(&mut runtime, &mut host, b"Retained", 4);
        let hwnd = window(&mut runtime, class, 1);
        assert_eq!(call(&mut runtime, &mut host, 132, hwnd, 0, Some(0xabcd_5678)), 0);
        assert_eq!(unregister(&mut runtime, &mut host, class.info.h_instance, atom(class)).unwrap(), 0);
        assert!(host.unregistrations.is_empty(), "live windows reject even a permissive host");
        runtime.win16.as_mut().unwrap().retire_window_handle(hwnd).unwrap();
        host.unregistration_result = failure;
        let result = unregister(&mut runtime, &mut host, class.info.h_instance, atom(class));
        match failure {
            HostResult::Refused => assert_eq!(result.unwrap(), 0),
            HostResult::Error => assert_eq!(result.unwrap_err().kind(), Kind::HostFailure),
            HostResult::Success => unreachable!(),
        }
        let state = runtime.win16.as_mut().unwrap();
        assert_eq!(state.window_classes.guest_class_extra_mut(class.class).unwrap(),
            &0xabcd_5678u32.to_le_bytes());
        assert_eq!(state.class_code_references(), vec![class.info.lpfn_wnd_proc]);
        assert!(state.is_registered_class_atom(class.atom));
        assert!(state.window_classes.menu_resource_for_host_class(class.class).is_some());
        host.unregistration_result = HostResult::Success;
        // Retry the retained registry operation even when dispatch stopped on
        // a real host error. The first attempt never consumed guest state.
        assert_eq!(state.unregister_class(class.info.h_instance, atom(class), &mut host).unwrap(), 1);
        assert!(state.window_classes.guest_class_extra_mut(class.class).is_none());
        assert!(state.class_code_references().is_empty());
        assert!(!state.is_registered_class_atom(class.atom));
        assert_eq!(state.window_classes.entries().count(), 0);
        assert_eq!(host.unregistrations, vec![class.class, class.class]);
    }
}

#[test]
fn unregister_class_name_success_releases_identity_and_reregistration_is_fresh() {
    let mut runtime = fixture();
    let mut host = ClassDataHost::default();
    let old = named_class(&mut runtime, &mut host, b"Recreate", 4);
    let hwnd = window(&mut runtime, old, 1);
    call(&mut runtime, &mut host, 132, hwnd, 0, Some(0x1234_5678));
    runtime.win16.as_mut().unwrap().retire_window_handle(hwnd).unwrap();
    let module = runtime.win16.as_ref().unwrap().modules.main;
    assert_eq!(unregister(&mut runtime, &mut host, module, name(b"RECREATE")).unwrap(), 1);
    assert_eq!(unregister(&mut runtime, &mut host, module, atom(old)).unwrap(), 0);
    let fresh = named_class(&mut runtime, &mut host, b"Recreate", 4);
    assert_ne!(fresh.class, old.class);
    assert_ne!(fresh.atom, old.atom);
    runtime.win16.as_mut().unwrap().next_window_handle = hwnd;
    let reused = window(&mut runtime, fresh, 2);
    assert_eq!(reused, hwnd);
    assert_eq!(call(&mut runtime, &mut host, 131, reused, 0, None), 0);
    assert_eq!(call(&mut runtime, &mut host, 129, reused, -32, None), u32::from(fresh.atom));
    assert_eq!(unregister(&mut runtime, &mut host, module, atom(old)).unwrap(), 0);
    assert_eq!(host.unregistrations, vec![old.class]);
}

#[test]
fn unregister_class_wrong_owner_name_atom_and_unavailable_module_never_reach_host() {
    let mut runtime = fixture();
    let mut host = ClassDataHost::default();
    let class = named_class(&mut runtime, &mut host, b"Owned", 0);
    for (owner, selector) in [
        (0, atom(class)), (0xffff, atom(class)), (class.info.h_instance, name(b"Other")),
        (class.info.h_instance, Win16ClassName::Atom(0)),
        (class.info.h_instance, Win16ClassName::Atom(0x4321)),
    ] {
        assert_eq!(unregister(&mut runtime, &mut host, owner, selector).unwrap(), 0);
    }
    // Keep the executing caller's module Ready. Retiring its own instance
    // would invalidate SS/DS backing at service entry, before USER.403 can
    // reject the target owner. Use a separate registration owner instead.
    let mut target_runtime = fixture();
    let target_state = target_runtime.win16.as_mut().unwrap();
    let mut target = target_state.modules.records.remove(&target_state.modules.main).unwrap();
    target.handle = 0xff10;
    target.instance = 0xff11;
    target.loaded = None;
    target.definition = None;
    target.allocations.clear();
    runtime.win16.as_mut().unwrap().modules.records.insert(target.handle, target);
    let mut info = class_info(&runtime, 0);
    info.h_instance = 0xff11;
    let unavailable_class = register(&mut runtime, &mut host, info, name(b"UnavailableOwner"));
    for unavailable in [ModuleState::Unloading, ModuleState::Retired] {
        runtime.win16.as_mut().unwrap().modules.records.get_mut(&0xff10).unwrap().state = unavailable;
        for owner in [0xff10, 0xff11] {
            assert_eq!(unregister(&mut runtime, &mut host, owner, atom(unavailable_class)).unwrap(), 0);
        }
    }
    assert!(host.unregistrations.is_empty());
    let state = runtime.win16.as_ref().unwrap();
    assert_eq!(state.modules.records[&state.modules.main].state, ModuleState::Ready);
    assert!(state.is_registered_class_atom(class.atom));
    assert!(state.is_registered_class_atom(unavailable_class.atom));
    assert_eq!(state.class_code_references(),
        vec![class.info.lpfn_wnd_proc, unavailable_class.info.lpfn_wnd_proc]);
}

#[test]
fn unregister_class_same_name_is_scoped_to_its_normalized_module_owner() {
    let mut runtime = fixture();
    let mut host = ClassDataHost::default();
    let first = named_class(&mut runtime, &mut host, b"SharedName", 0);
    let mut other_runtime = fixture();
    let other_state = other_runtime.win16.as_mut().unwrap();
    let mut other = other_state.modules.records.remove(&other_state.modules.main).unwrap();
    other.handle = 0xff10;
    other.instance = 0xff11;
    other.loaded = None;
    other.definition = None;
    other.allocations.clear();
    runtime.win16.as_mut().unwrap().modules.records.insert(other.handle, other);
    let mut info = class_info(&runtime, 0);
    info.h_instance = 0xff11;
    let second = register(&mut runtime, &mut host, info, name(b"SharedName"));
    assert_eq!(unregister(&mut runtime, &mut host, 0xff10, atom(first)).unwrap(), 0);
    assert_eq!(unregister(&mut runtime, &mut host, 0xff10, name(b"sharedname")).unwrap(), 1);
    assert_eq!(host.unregistrations, vec![second.class]);
    assert!(runtime.win16.as_ref().unwrap().is_registered_class_atom(first.atom));
    assert_eq!(unregister(&mut runtime, &mut host, first.info.h_instance, atom(first)).unwrap(), 1);
}

#[test]
fn unregister_class_predefined_alias_is_not_an_application_registration() {
    let mut runtime = fixture();
    let mut host = ClassDataHost::default();
    let owner = class_info(&runtime, 0).h_instance;
    let system = runtime.win16.as_mut().unwrap().resolve_window_class_for_create(
        owner, &name(b"BUTTON"), &mut host).unwrap().unwrap();
    assert_eq!(unregister(&mut runtime, &mut host, owner, name(b"button")).unwrap(), 0);
    assert!(host.unregistrations.is_empty());
    let custom = named_class(&mut runtime, &mut host, b"BUTTON", 0);
    assert_eq!(unregister(&mut runtime, &mut host, owner, atom(custom)).unwrap(), 1);
    assert_eq!(runtime.win16.as_ref().unwrap().window_classes.system_kind_for_host_class(system.host_class),
        Some(Win16HostSystemClass::Button));
    assert_eq!(host.unregistrations, vec![custom.class]);
}

#[test]
fn unregister_class_revalidates_source_atom_alias_and_uses_host_dbcs_case_rules() {
    let mut runtime = fixture();
    let mut host = ClassDataHost { dbcs_case: true, atom_name: Some((0xc246, b"\x82AClass".to_vec())),
        ..ClassDataHost::default() };
    let info = class_info(&runtime, 0);
    let class = register(&mut runtime, &mut host, info, Win16ClassName::Atom(0xc246));
    assert_eq!(unregister(&mut runtime, &mut host, info.h_instance, name(b"\x82aclass")).unwrap(), 0);
    host.atom_name = Some((0xc246, b"Reused".to_vec()));
    assert_eq!(unregister(&mut runtime, &mut host, info.h_instance, Win16ClassName::Atom(0xc246)).unwrap(), 0);
    host.atom_name = Some((0xc246, Vec::new()));
    assert_eq!(unregister(&mut runtime, &mut host, info.h_instance, Win16ClassName::Atom(0xc246)).unwrap(), 0);
    assert!(host.unregistrations.is_empty());
    host.atom_name = Some((0xc246, b"\x82ACLASS".to_vec()));
    assert_eq!(unregister(&mut runtime, &mut host, info.h_instance, Win16ClassName::Atom(0xc246)).unwrap(), 1);
    assert_eq!(host.unregistrations, vec![class.class]);
}

fn push_operation(runtime: &mut Runtime, continuation: WindowReturn) {
    let state = runtime.win16.as_mut().unwrap();
    state.window_dispatch_context = Some(runtime.cpu.capture_context());
    state.push_window_operation(runtime.cpu.regs.clone(), (runtime.cpu.regs.cs, 0x12, 0x80),
        continuation).unwrap();
    state.window_dispatch_context = None;
}

#[test]
fn unregister_class_retains_an_inflight_create_before_any_guest_hwnd_exists() {
    let mut runtime = fixture();
    let mut host = ClassDataHost::default();
    let class = named_class(&mut runtime, &mut host, b"Creating", 0);
    let other = named_class(&mut runtime, &mut host, b"Unrelated", 0);
    push_operation(&mut runtime, WindowReturn::Create {
        creation: crate::Win16CreationId(1),
        request: WindowCreateRequest {
            class_name: atom(class), window_name: None, ex_style: 0, style: 0,
            x: 0, y: 0, width: 1, height: 1, parent: 0, menu: 0,
            instance: class.info.h_instance, parameter: 0,
        },
        procedure: WindowProcedure { class: class.class, address: class.info.lpfn_wnd_proc,
            instance: class.info.h_instance },
        window: None, parent_was_updated: false,
    });
    assert_eq!(unregister(&mut runtime, &mut host, class.info.h_instance, atom(class)).unwrap(), 0);
    assert_eq!(unregister(&mut runtime, &mut host, other.info.h_instance, atom(other)).unwrap(), 1);
    assert_eq!(host.unregistrations, vec![other.class]);
    runtime.win16.as_mut().unwrap().window_operations.pop();
    assert_eq!(unregister(&mut runtime, &mut host, class.info.h_instance, atom(class)).unwrap(), 1);
}

fn callback(runtime: &mut Runtime, class: Registered, hwnd: u16, native: Win16HostWindow) {
    let state = runtime.win16.as_mut().unwrap();
    state.window_callbacks.push(WindowCallbackFrame::guest(
        crate::win16_runtime::CallbackFrameId(1), runtime.cpu.regs.clone(),
        crate::win16_runtime::window_payloads::GuestWindowPayload {
            message: 0x111, w_param: 0, l_param: 0, allocation: None, output: None,
            callback_dc: None, command_control: None, command_parent: None, common_dialog_request: None,
        }, None, class.info.lpfn_wnd_proc, WindowClassRoot::Class(class.class), None, None,
        WindowCallbackContinuation::Host { callback: crate::Win16HostCallback(1),
            native_window: native, window: hwnd, destroyed: false },
    ));
}

#[test]
fn unregister_class_retains_exact_registration_after_hwnd_retirement_and_reuse() {
    let mut runtime = fixture();
    let mut host = ClassDataHost::default();
    let active = named_class(&mut runtime, &mut host, b"Active", 0);
    let other = named_class(&mut runtime, &mut host, b"Other", 0);
    let hwnd = window(&mut runtime, active, 1);
    let native = runtime.win16.as_ref().unwrap().window_handles[&hwnd];
    callback(&mut runtime, active, hwnd, native);
    assert_eq!(unregister(&mut runtime, &mut host, other.info.h_instance, atom(other)).unwrap(), 1);
    runtime.win16.as_mut().unwrap().retire_window_handle(hwnd).unwrap();
    let replacement = named_class(&mut runtime, &mut host, b"Replacement", 0);
    runtime.win16.as_mut().unwrap().next_window_handle = hwnd;
    assert_eq!(window(&mut runtime, replacement, 2), hwnd);
    assert_eq!(unregister(&mut runtime, &mut host, active.info.h_instance, atom(active)).unwrap(), 0);
    assert!(!host.diagnostics.contains(&Kind::CompatibilityGap));
    assert_eq!(host.unregistrations, vec![other.class]);
    runtime.win16.as_mut().unwrap().retire_window_handle(hwnd).unwrap();
    assert_eq!(unregister(&mut runtime, &mut host, replacement.info.h_instance, atom(replacement)).unwrap(), 1);
    runtime.win16.as_mut().unwrap().window_callbacks.pop();
    assert_eq!(unregister(&mut runtime, &mut host, active.info.h_instance, atom(active)).unwrap(), 1);
}

#[test]
fn unregister_class_retains_all_mdi_creation_continuations_without_live_child_hwnds() {
    use crate::win16_runtime::{
        guest_ranges::GuestOutputRange, messages::MessageOutput,
        messages_mdi::{MdiCreateOutputPlan, MdiOutputPlan},
        user_services_controls::{FamilyCompletion, Win16UserFamilyContinuation},
    };
    for route in 0..3 {
        let mut runtime = fixture();
        let mut host = ClassDataHost::default();
        let class = named_class(&mut runtime, &mut host, b"MdiPending", 0);
        let other = named_class(&mut runtime, &mut host, b"MdiUnrelated", 0);
        let state = runtime.win16.as_ref().unwrap();
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
        let continuation = match route {
            0 => WindowReturn::Message { output: MessageOutput::Mdi(Some(MdiOutputPlan::Create(plan))) },
            1 => WindowReturn::DispatchMessage { mdi_output: Some(MdiOutputPlan::Create(plan)) },
            _ => WindowReturn::UserFamily(Win16UserFamilyContinuation {
                return_kind: Win16ReturnKind::Dword,
                completion: FamilyCompletion::DialogDefaultProcedure {
                    output: MessageOutput::Mdi(Some(MdiOutputPlan::Create(plan))),
                },
                dialog_window: None, dialog_window_destroyed: false,
            }),
        };
        push_operation(&mut runtime, continuation);
        assert_eq!(unregister(&mut runtime, &mut host, class.info.h_instance, atom(class)).unwrap(), 0);
        assert_eq!(unregister(&mut runtime, &mut host, other.info.h_instance, atom(other)).unwrap(), 1);
        assert_eq!(host.unregistrations, vec![other.class]);
        assert!(runtime.win16.as_ref().unwrap().is_registered_class_atom(class.atom));
        runtime.win16.as_mut().unwrap().window_operations.pop();
        assert_eq!(unregister(&mut runtime, &mut host, class.info.h_instance, atom(class)).unwrap(), 1);
    }
}

#[test]
fn unregister_class_registration_atoms_outrank_stale_source_aliases_across_owners() {
    let mut runtime = fixture();
    let mut host = ClassDataHost { atom_name: Some((0xa002, b"Alias".to_vec())),
        ..ClassDataHost::default() };
    let info = class_info(&runtime, 0);
    let first = register(&mut runtime, &mut host, info, Win16ClassName::Atom(0xa002));
    let mut other_runtime = fixture();
    let other_state = other_runtime.win16.as_mut().unwrap();
    let mut other = other_state.modules.records.remove(&other_state.modules.main).unwrap();
    other.handle = 0xff10;
    other.instance = 0xff11;
    other.loaded = None;
    other.definition = None;
    other.allocations.clear();
    runtime.win16.as_mut().unwrap().modules.records.insert(other.handle, other);
    let second = register(&mut runtime, &mut host, WndClass16 { h_instance: 0xff11, ..info }, name(b"Second"));
    assert_eq!(second.atom, 0xa002);
    assert_eq!(unregister(&mut runtime, &mut host, info.h_instance, atom(second)).unwrap(), 0);
    assert!(host.unregistrations.is_empty());
    assert_eq!(unregister(&mut runtime, &mut host, info.h_instance, atom(first)).unwrap(), 1);
    assert_eq!(host.unregistrations, vec![first.class]);
    assert!(runtime.win16.as_ref().unwrap().is_registered_class_atom(second.atom));
}

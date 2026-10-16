//! Win16 class-procedure replacement, saved chains, and code-owner lifetime.

use super::*;
use crate::win16_runtime::{
    module_memory::ModuleAllocation,
    module_registry::ModuleState,
    windows::{WindowCallbackContinuation, WindowClassRoot},
};
use guest_core::{GuestMemory, PhysAddr, io::NoPorts};
use win16_abi::{Access, AccessRights};

const GCL_WNDPROC: i16 = -24;
const GWL_WNDPROC: i16 = -4;

fn enter_native_subclass_send(runtime: &mut Runtime, host: &mut ClassDataHost, hwnd: u16, message: u16)
    -> Result<Option<u8>, RuntimeError>
{
    let descriptor = lookup_export(b"USER", ExportLookupTarget::Ordinal(111)).unwrap();
    let stack = runtime.cpu.regs.sp();
    let mut bytes = Vec::from(0x12_u16.to_le_bytes());
    bytes.extend_from_slice(&runtime.cpu.regs.cs.to_le_bytes());
    bytes.extend_from_slice(&0x1234_5678_u32.to_le_bytes());
    bytes.extend_from_slice(&0x1357_u16.to_le_bytes());
    bytes.extend_from_slice(&message.to_le_bytes());
    bytes.extend_from_slice(&hwnd.to_le_bytes());
    let state = runtime.win16.as_mut().unwrap();
    let pointer = state.selectors.pointer_from_raw(Selector(runtime.cpu.regs.ss), stack).unwrap();
    state.selectors.write(&mut runtime.memory, pointer, &bytes).unwrap();
    let slot = state.bindings.len();
    state.bindings.push(ImportBinding::Supported(descriptor));
    runtime.cpu.regs.cs = state.gate_selector.0;
    runtime.cpu.regs.set_ip((slot * 2) as u16);
    state.dispatch(&mut runtime.cpu, &mut runtime.memory, &mut runtime.dos, host, 0)
}

#[test]
fn class_data_native_subclass_enters_guest_and_resumes_the_exact_send_message_caller() {
    for (registered, message) in [(false, 0x100_u16), (false, 0x401), (true, 0x100), (true, 0x401)] {
        let mut runtime = fixture();
        let native = Win16HostWindow(0x5555);
        let mut host = ClassDataHost {
            subclass_window: Some(native), subclass_set_succeeded: true,
            subclass_callback_source: Some(crate::Win16NativeCallbackSource::WindowMessage {
                window: native, class: None, message: u32::from(message),
            }),
            ..Default::default()
        };
        let class = registered.then(|| named_class(&mut runtime, &mut host, b"NativeEntry", 4));
        let state = runtime.win16.as_mut().unwrap();
        let hwnd = state.allocate_window_handle(native).unwrap();
        state.initialize_window_data(hwnd, class.map(|class| class.class), 0x2222, false, None).unwrap();
        let root = state.window_class_root(hwnd);
        let target = procedure(&runtime, 0x40);
        assert_ne!(call(&mut runtime, &mut host, 136, hwnd, GWL_WNDPROC, Some(target)), 0);
        let caller = (runtime.cpu.regs.cs, runtime.cpu.regs.sp());
        enter_native_subclass_send(&mut runtime, &mut host, hwnd, message).unwrap();
        let state = runtime.win16.as_ref().unwrap();
        let frame = state.window_callbacks.last().unwrap();
        assert_eq!(frame.class_root, root);
        assert_eq!(frame.callback_address, target);
        assert_eq!((runtime.cpu.regs.cs, runtime.cpu.regs.ip(), runtime.cpu.regs.ax()),
            ((target >> 16) as u16, target as u16, 0x2222));
        let pointer = state.selectors.pointer_from_raw(Selector(runtime.cpu.regs.ss), runtime.cpu.regs.sp()).unwrap();
        let mut arguments = [0; 14];
        state.selectors.read(&runtime.memory, pointer, &mut arguments).unwrap();
        assert_eq!(&arguments[4..8], &0x1234_5678_u32.to_le_bytes());
        assert_eq!(&arguments[8..10], &0x1357_u16.to_le_bytes());
        assert_eq!(&arguments[10..12], &message.to_le_bytes());
        assert_eq!(&arguments[12..14], &hwnd.to_le_bytes());
        // A nested real service gate advances the CPU boundary sequence.
        let callback_sp = runtime.cpu.regs.sp();
        runtime.cpu.regs.set_sp(callback_sp - 12);
        assert_eq!(call(&mut runtime, &mut host, 135, hwnd, GWL_WNDPROC, None), target);
        runtime.cpu.regs.set_sp(callback_sp);
        return_saved_procedure(&mut runtime, &mut host, 0x89ab_cdef);
        assert_eq!((runtime.cpu.regs.cs, runtime.cpu.regs.ip(), runtime.cpu.regs.sp()),
            (caller.0, 0x12, caller.1 + 14));
        let state = runtime.win16.as_ref().unwrap();
        assert_eq!(state.window_class_root(hwnd), root);
        assert!(state.window_callbacks.is_empty());
        assert!(state.window_operations.is_empty());
        assert!(state.legacy_cpu_frames.is_empty());
        assert_eq!(host.subclass_replies.len(), 1);
        assert_eq!(host.subclass_replies[0].result.value, 0x89ab_cdef);
        host.subclass_consumed.sort_unstable();
        assert_eq!(host.subclass_consumed, [1, 2, 3]);
    }
}

#[test]
fn class_data_native_subclass_rejects_a_different_window_or_class_route_before_guest_entry() {
    for wrong_window in [false, true] {
        let mut runtime = fixture();
        let native = Win16HostWindow(0x5555);
        let mut host = ClassDataHost {
            subclass_window: Some(native), subclass_set_succeeded: true,
            ..Default::default()
        };
        let class = named_class(&mut runtime, &mut host, b"WrongSource", 4);
        let state = runtime.win16.as_mut().unwrap();
        let hwnd = state.allocate_window_handle(native).unwrap();
        state.initialize_window_data(hwnd, Some(class.class), 0x2222, false, None).unwrap();
        let target = procedure(&runtime, 0x40);
        call(&mut runtime, &mut host, 136, hwnd, GWL_WNDPROC, Some(target));
        host.subclass_callback_source = Some(crate::Win16NativeCallbackSource::WindowMessage {
            window: if wrong_window { Win16HostWindow(0x6666) } else { native },
            class: (!wrong_window).then_some(class.class), message: 0x100,
        });
        assert!(enter_native_subclass_send(&mut runtime, &mut host, hwnd, 0x100).is_err());
        let state = runtime.win16.as_ref().unwrap();
        let frame = state.window_callbacks.last().unwrap();
        assert_eq!(frame.entry_phase, crate::win16_runtime::windows::WindowCallbackEntryPhase::SetupFailed);
        assert!(frame.setup_error.is_some());
        assert_eq!(state.window_class_root(hwnd), WindowClassRoot::Class(class.class));
        assert_eq!(state.native_subclass_procedure(hwnd), Some((target, 0x2222)));
        assert_eq!(state.window_operations.len(), 1, "failed setup retains its cancellable native owner");
        assert!(host.subclass_replies.is_empty());
        host.subclass_consumed.sort_unstable();
        assert_eq!(host.subclass_consumed, [1, 2]);
    }
}

#[test]
fn class_data_registered_callback_still_requires_its_exact_native_class_source() {
    for mismatch in 0..3 {
        let mut runtime = fixture();
        let mut host = ClassDataHost::default();
        let class = named_class(&mut runtime, &mut host, b"SelectedClass", 4);
        let other = named_class(&mut runtime, &mut host, b"SameFarOtherClass", 4);
        assert_eq!(class.info.lpfn_wnd_proc, other.info.lpfn_wnd_proc);
        let hwnd = window(&mut runtime, class, 1);
        let state = runtime.win16.as_mut().unwrap();
        let native = state.window_handles[&hwnd];
        let procedure = state.window_procedures[&hwnd];
        let source = crate::Win16NativeCallbackSource::WindowMessage {
            window: if mismatch == 2 { Win16HostWindow(0x6666) } else { native },
            class: match mismatch { 0 => None, 1 => Some(other.class), _ => Some(class.class) },
            message: 0x100,
        };
        assert!(state.begin_host_window_callback(&mut runtime.cpu.regs, &mut runtime.memory,
            &mut host, crate::Win16HostWindowOperationId(1), crate::Win16HostCallback(2),
            native, hwnd, procedure, crate::Win16HostMessage::Scalar {
                kind: crate::Win16ScalarMessage::KeyDown, w_param: 7, l_param: 9,
            }, None, source, false).is_err());
        assert_eq!(state.window_class_root(hwnd), WindowClassRoot::Class(class.class));
        assert_eq!(state.window_callbacks.last().unwrap().entry_phase,
            crate::win16_runtime::windows::WindowCallbackEntryPhase::SetupFailed);
    }
}

#[test]
fn class_data_native_subclass_callback_preserves_the_window_class_provenance() {
    for registered in [false, true] {
        let mut runtime = fixture();
        let native = Win16HostWindow(0x5555);
        let mut host = ClassDataHost {
            subclass_window: Some(native), subclass_set_succeeded: true,
            ..Default::default()
        };
        let class = registered.then(|| named_class(&mut runtime, &mut host, b"NativeControl", 4));
        let state = runtime.win16.as_mut().unwrap();
        let hwnd = state.allocate_window_handle(native).unwrap();
        state.initialize_window_data(hwnd, class.map(|class| class.class), 0x2222, false, None).unwrap();
        let root = state.window_class_root(hwnd);
        let replacement = procedure(&runtime, 0x40);
        assert_ne!(call(&mut runtime, &mut host, 136, hwnd, GWL_WNDPROC, Some(replacement)), 0);
        let state = runtime.win16.as_mut().unwrap();
        let (target, address, instance, callback_root) = state.native_subclass_callback_owner(native).unwrap();
        assert_eq!((target, address, instance), (hwnd, replacement, 0x2222));
        assert_eq!(callback_root, root);
        state.record_window_class_root(target, native, callback_root).unwrap();
        assert_eq!(state.window_class_root(hwnd), root);
        assert_eq!(state.window_host_class(hwnd), class.map(|class| class.class));
        assert!(state.window_operations.is_empty());
        assert!(state.legacy_cpu_frames.is_empty());
    }
}

#[test]
fn class_data_native_subclass_sync_followup_returns_without_redispatching_the_gate() {
    for succeeded in [false, true] {
        let mut runtime = fixture();
        let native = Win16HostWindow(0x5555);
        let state = runtime.win16.as_mut().unwrap();
        let hwnd = state.allocate_window_handle(native).unwrap();
        state.initialize_window_data(hwnd, None, 0x2222, false, None).unwrap();
        let replacement = procedure(&runtime, 0x40);
        let mut host = ClassDataHost {
            subclass_window: Some(native), subclass_set_succeeded: succeeded,
            ..Default::default()
        };
        let old = call(&mut runtime, &mut host, 136, hwnd, GWL_WNDPROC, Some(replacement));
        let state = runtime.win16.as_ref().unwrap();
        if succeeded {
            assert_eq!(state.native_procedure_for_address(old), Some(Win16HostProcedure(0x1234_5678_9abc_def0)));
            assert_eq!(state.native_subclass_procedure(hwnd), Some((replacement, 0x2222)));
        } else {
            assert_eq!(old, 0);
            assert!(state.native_subclass_procedure(hwnd).is_none());
        }
        assert_eq!(host.subclass_sources.len(), 2);
        let mut consumed = host.subclass_consumed;
        consumed.sort_unstable();
        assert_eq!(consumed, [1, 2]);
        assert!(state.window_operations.is_empty());
        assert!(state.legacy_cpu_frames.is_empty());
    }
}

fn procedure(runtime: &Runtime, offset: u16) -> u32 {
    (u32::from(runtime.cpu.regs.cs) << 16) | u32::from(offset)
}

fn assert_class_roots(runtime: &Runtime, expected: &[u32]) {
    let mut actual = runtime.win16.as_ref().unwrap().class_code_references();
    actual.sort_unstable();
    actual.dedup();
    let mut expected = expected.to_vec();
    expected.sort_unstable();
    expected.dedup();
    assert_eq!(actual, expected);
}

fn assert_window_roots(runtime: &Runtime, expected: &[u32]) {
    let mut actual: Vec<_> = runtime.win16.as_ref().unwrap().window_procedure_roots().collect();
    actual.sort_unstable();
    let mut expected = expected.to_vec();
    expected.sort_unstable();
    assert_eq!(actual, expected, "saved HWND procedure roots must be deduplicated");
}

// Unlike the initial-window fixture, this copies the procedure from
// the same current registry resolution used by future CreateWindow calls.
fn future_window(runtime: &mut Runtime, host: &mut ClassDataHost, class: Registered, native: u64) -> u16 {
    let state = runtime.win16.as_mut().unwrap();
    let resolved = state.resolve_window_class_for_create(class.info.h_instance,
        &Win16ClassName::Atom(class.atom), host).unwrap().unwrap();
    assert_eq!(resolved.host_class, class.class);
    assert_eq!(resolved.instance, class.info.h_instance);
    let hwnd = state.allocate_window_handle(Win16HostWindow(0xfedc_0000_0000 + native)).unwrap();
    state.initialize_window_data(hwnd, Some(resolved.host_class), resolved.instance,
        false, Some(resolved.window_extra_bytes)).unwrap();
    state.window_procedures.insert(hwnd, WindowProcedure {
        class: resolved.host_class, address: resolved.wnd_proc, instance: resolved.instance,
    });
    hwnd
}

#[test]
fn class_data_procedure_gate_returns_old_class_and_changes_only_selected_existing_window() {
    let mut runtime = fixture();
    let mut host = ClassDataHost::default();
    let class = named_class(&mut runtime, &mut host, b"Replace", 4);
    let selected = window(&mut runtime, class, 1);
    let sibling = window(&mut runtime, class, 2);
    let p = class.info.lpfn_wnd_proc;
    let s = procedure(&runtime, 0x40);
    let n = procedure(&runtime, 0x60);
    assert_eq!(call(&mut runtime, &mut host, 136, selected, GWL_WNDPROC, Some(s)), p);
    assert_eq!(call(&mut runtime, &mut host, 132, selected, 0, Some(0x1234_5678)), 0);
    // call() checks the physical Pascal frame, complete cleanup and DX:AX.
    assert_eq!(call(&mut runtime, &mut host, 132, selected, GCL_WNDPROC, Some(n)), p);
    for hwnd in [selected, sibling] {
        assert_eq!(call(&mut runtime, &mut host, 131, hwnd, GCL_WNDPROC, None), n);
        assert_eq!(call(&mut runtime, &mut host, 131, hwnd, 0, None), 0x1234_5678);
    }
    assert_eq!(call(&mut runtime, &mut host, 135, selected, GWL_WNDPROC, None), n);
    assert_eq!(call(&mut runtime, &mut host, 135, sibling, GWL_WNDPROC, None), p);
    assert_class_roots(&runtime, &[p, n]);
    assert_window_roots(&runtime, &[p, s]);
    let future = future_window(&mut runtime, &mut host, class, 3);
    assert_eq!(call(&mut runtime, &mut host, 135, future, GWL_WNDPROC, None), n);
    assert_eq!(runtime.win16.as_ref().unwrap().window_procedures[&selected].instance,
        class.info.h_instance);
    assert_eq!(host.registrations.len(), 1, "replacement must not register a new host class");
    assert!(host.unregistrations.is_empty());
    assert!(host.diagnostics.is_empty());
}

#[test]
fn class_data_procedure_get_class_info_reports_replacement_and_preserves_name_outputs() {
    let mut runtime = fixture();
    let mut host = ClassDataHost::default();
    let class = named_class(&mut runtime, &mut host, b"Metadata", 7);
    let hwnd = window(&mut runtime, class, 1);
    let replacement = procedure(&runtime, 0x60);
    assert_eq!(call(&mut runtime, &mut host, 132, hwnd, GCL_WNDPROC, Some(replacement)),
        class.info.lpfn_wnd_proc);
    let state = runtime.win16.as_mut().unwrap();
    let output = (u32::from(runtime.cpu.regs.ds) << 16) | 0x20;
    let pointer = state.selectors.pointer_from_far(output).unwrap();
    let sentinel = [0xa5; WndClass16::SIZE];
    for name in [Win16ClassName::Atom(class.atom), Win16ClassName::Name(b"METADATA".to_vec())] {
        state.selectors.write(&mut runtime.memory, pointer, &sentinel).unwrap();
        assert_eq!(state.get_class_info(class.info.h_instance, name, output,
            &mut runtime.memory, &mut host).unwrap(), 1);
        let mut actual = [0; WndClass16::SIZE];
        state.selectors.read(&runtime.memory, pointer, &mut actual).unwrap();
        let expected = WndClass16 { lpfn_wnd_proc: replacement, ..class.info }.encode();
        let names_start = win16_abi::wndclass16_offsets::LPSZ_MENU_NAME;
        assert_eq!(&actual[..names_start], &expected[..names_start]);
        assert_eq!(&actual[names_start..], &sentinel[names_start..]);
    }
    let resolved = state.resolve_window_class_for_create(class.info.h_instance,
        &Win16ClassName::Name(b"metadata".to_vec()), &mut host).unwrap().unwrap();
    assert_eq!(resolved.wnd_proc, replacement);
    assert_eq!(resolved.host_class, class.class);
    assert_eq!(resolved.window_extra_bytes, class.info.cb_wnd_extra as usize);
}

#[test]
fn class_data_procedure_mixed_noops_update_both_owners_and_do_not_grow_saved_roots() {
    for class_already_matches in [false, true] {
        let mut runtime = fixture();
        let mut host = ClassDataHost::default();
        let class = named_class(&mut runtime, &mut host, b"Mixed", 0);
        let hwnd = window(&mut runtime, class, 1);
        let p = class.info.lpfn_wnd_proc;
        let s = procedure(&runtime, 0x40);
        let n = procedure(&runtime, 0x60);
        assert_eq!(call(&mut runtime, &mut host, 132, hwnd, GCL_WNDPROC, Some(p)), p);
        assert_eq!(runtime.win16.as_ref().unwrap().class_code_references(), vec![p]);
        assert_window_roots(&runtime, &[]);
        if class_already_matches {
            assert_eq!(call(&mut runtime, &mut host, 132, hwnd, GCL_WNDPROC, Some(n)), p);
            assert_eq!(call(&mut runtime, &mut host, 136, hwnd, GWL_WNDPROC, Some(s)), n);
        } else {
            assert_eq!(call(&mut runtime, &mut host, 136, hwnd, GWL_WNDPROC, Some(n)), p);
        }
        assert_eq!(call(&mut runtime, &mut host, 132, hwnd, GCL_WNDPROC, Some(n)),
            if class_already_matches { n } else { p });
        assert_eq!(call(&mut runtime, &mut host, 131, hwnd, GCL_WNDPROC, None), n);
        assert_eq!(call(&mut runtime, &mut host, 135, hwnd, GWL_WNDPROC, None), n);
        assert_class_roots(&runtime, &[p, n]);
        let class_count = runtime.win16.as_ref().unwrap().class_code_references().len();
        let window_count = runtime.win16.as_ref().unwrap().window_procedure_roots().count();
        for _ in 0..8 {
            assert_eq!(call(&mut runtime, &mut host, 132, hwnd, GCL_WNDPROC, Some(n)), n);
            assert_eq!(runtime.win16.as_ref().unwrap().class_code_references().len(), class_count);
            assert_eq!(runtime.win16.as_ref().unwrap().window_procedure_roots().count(), window_count);
        }
        let roots: Vec<_> = runtime.win16.as_ref().unwrap().window_procedure_roots().collect();
        assert_eq!(roots.iter().filter(|&&root| root == p).count(), 1);
        assert_eq!(roots.iter().filter(|&&root| root == s).count(), usize::from(class_already_matches));
        // Restoring and replacing old values must reuse their historical roots.
        for replacement in [p, n, p, n] {
            let old = call(&mut runtime, &mut host, 131, hwnd, GCL_WNDPROC, None);
            assert_eq!(call(&mut runtime, &mut host, 132, hwnd, GCL_WNDPROC, Some(replacement)), old);
        }
        let roots: Vec<_> = runtime.win16.as_ref().unwrap().window_procedure_roots().collect();
        assert_eq!(roots.iter().filter(|&&root| root == p).count(), 1);
        assert_eq!(roots.iter().filter(|&&root| root == n).count(), 1);
        assert_class_roots(&runtime, &[p, n]);
        assert!(runtime.win16.as_ref().unwrap().class_code_references().len() <= 3,
            "each historical class FAR is retained at most once, alongside the current FAR");
        assert!(host.diagnostics.is_empty());
    }
}

// Exercise the real USER.122 import gate and inspect its emitted FAR callback
// stack; returning through the ordinary callback completion checks DX:AX too.
fn enter_saved_procedure(runtime: &mut Runtime, host: &mut ClassDataHost, target: u32, hwnd: u16) {
    let descriptor = lookup_export(b"USER", ExportLookupTarget::Ordinal(122)).unwrap();
    assert_eq!(descriptor.return_kind, Win16ReturnKind::Dword);
    let Win16ExportStackCleanup::Fixed(cleanup) = descriptor.stack_cleanup else { panic!("fixed frame") };
    assert_eq!(cleanup.callee_pop_bytes, 14);
    assert_eq!(cleanup.caller_pop_bytes, 0);
    let return_cs = runtime.cpu.regs.cs;
    // Model the caller pushing its FAR return and Pascal arguments below
    // its live stack. Nested API calls must not overwrite the outer callback.
    let stack = runtime.cpu.regs.sp().checked_sub(18).unwrap();
    runtime.cpu.regs.set_sp(stack);
    let mut bytes = vec![0x12, 0];
    bytes.extend_from_slice(&return_cs.to_le_bytes());
    bytes.extend_from_slice(&0x1234_5678_u32.to_le_bytes());
    bytes.extend_from_slice(&0x1357_u16.to_le_bytes());
    bytes.extend_from_slice(&0x100_u16.to_le_bytes());
    bytes.extend_from_slice(&hwnd.to_le_bytes());
    bytes.extend_from_slice(&target.to_le_bytes());
    let state = runtime.win16.as_mut().unwrap();
    let pointer = state.selectors.pointer_from_raw(Selector(runtime.cpu.regs.ss), stack).unwrap();
    state.selectors.write(&mut runtime.memory, pointer, &bytes).unwrap();
    let slot = state.bindings.len();
    state.bindings.push(ImportBinding::Supported(descriptor));
    runtime.cpu.regs.cs = state.gate_selector.0;
    runtime.cpu.regs.set_ip((slot * 2) as u16);
    assert_eq!(state.dispatch(&mut runtime.cpu, &mut runtime.memory, &mut runtime.dos, host, 0).unwrap(), None);
    assert_eq!((runtime.cpu.regs.cs, runtime.cpu.regs.ip()), ((target >> 16) as u16, target as u16));
    let frame = state.window_callbacks.last().unwrap();
    assert_eq!(frame.callback_address, target);
    assert_eq!(frame.class_root, WindowClassRoot::NoRegistration);
    assert!(matches!(frame.continuation, WindowCallbackContinuation::GuestProcedureCall { forwarded: None }));
    let pointer = state.selectors.pointer_from_raw(Selector(runtime.cpu.regs.ss), runtime.cpu.regs.sp()).unwrap();
    let mut callback = [0; 14];
    state.selectors.read(&runtime.memory, pointer, &mut callback).unwrap();
    assert_eq!(&callback[..2], &[0, 0]);
    assert_eq!(&callback[2..4], &state.callback_gate_selector.0.to_le_bytes());
    assert_eq!(&callback[4..], &bytes[4..14]);
}

fn return_saved_procedure(runtime: &mut Runtime, host: &mut ClassDataHost, value: u32) {
    let state = runtime.win16.as_mut().unwrap();
    let frame = state.window_callbacks.last().unwrap();
    // A real RETF 10 proves the guest return boundary even after a nested
    // USER call advanced the CPU's call-boundary sequence. The return stub
    // stays clear of the registered, subclassed and replacement entrypoints.
    let code = (frame.callback_address & 0xffff_0000) | 0x80;
    let pointer = state.selectors.pointer_from_far(code).unwrap();
    let physical = state.selectors.translate(pointer, Access::Execute, 3,
        &runtime.memory).unwrap();
    runtime.memory.write(physical, &[0xca, 10, 0]).unwrap();
    runtime.cpu.regs.cs = (code >> 16) as u16;
    runtime.cpu.regs.set_ip(code as u16);
    runtime.cpu.regs.ss = frame.saved.ss;
    runtime.cpu.regs.set_sp(frame.saved.sp() - 14);
    runtime.cpu.regs.set_ax(value as u16);
    runtime.cpu.regs.set_dx((value >> 16) as u16);
    let segments = crate::win16_loader::Win16Segments {
        selectors: &state.selectors, memory_len: runtime.memory.len(),
    };
    assert_eq!(runtime.cpu.step_with_context(&mut runtime.memory.bus(), &mut NoPorts,
        &segments).unwrap(), x86_cpu::StepOutcome::Continue);
    assert_eq!(runtime.cpu.control_transfer(), Some(x86_cpu::ControlTransfer::FarReturn));
    state.record_window_callback_return(crate::win16_runtime::CallbackKind::Window,
        x86_cpu::ControlTransfer::FarReturn).unwrap();
    state.finish_window_callback(&mut runtime.cpu.regs, &mut runtime.memory, host).unwrap();
    state.drive_pending_window_completion(&mut runtime.cpu, &mut runtime.memory,
        &mut runtime.dos, host).unwrap();
    assert_eq!(u32::from(runtime.cpu.regs.ax()) | (u32::from(runtime.cpu.regs.dx()) << 16), value);
}

#[test]
fn class_data_procedure_saved_class_and_displaced_subclass_remain_callable_as_nested_chain() {
    let mut runtime = fixture();
    let mut host = ClassDataHost::default();
    let class = named_class(&mut runtime, &mut host, b"Chain", 0);
    let hwnd = window(&mut runtime, class, 1);
    let p = class.info.lpfn_wnd_proc;
    let s = procedure(&runtime, 0x40);
    let n = procedure(&runtime, 0x60);
    assert_eq!(call(&mut runtime, &mut host, 136, hwnd, GWL_WNDPROC, Some(s)), p);
    let saved_subclass = call(&mut runtime, &mut host, 135, hwnd, GWL_WNDPROC, None);
    let saved_class = call(&mut runtime, &mut host, 132, hwnd, GCL_WNDPROC, Some(n));
    assert_eq!((saved_class, saved_subclass), (p, s));
    let caller = (runtime.cpu.regs.cs, runtime.cpu.regs.sp());
    enter_saved_procedure(&mut runtime, &mut host, saved_subclass, hwnd);
    let outer_stack = runtime.cpu.regs.sp();
    let outer_bytes = {
        let state = runtime.win16.as_ref().unwrap();
        let pointer = state.selectors.pointer_from_raw(Selector(runtime.cpu.regs.ss), outer_stack).unwrap();
        let mut bytes = [0; 14];
        state.selectors.read(&runtime.memory, pointer, &mut bytes).unwrap();
        bytes
    };
    enter_saved_procedure(&mut runtime, &mut host, saved_class, hwnd);
    assert_eq!(runtime.win16.as_ref().unwrap().window_callbacks.len(), 2);
    return_saved_procedure(&mut runtime, &mut host, 0x89ab_cdef);
    assert_eq!((runtime.cpu.regs.cs, runtime.cpu.regs.ip(), runtime.cpu.regs.sp()),
        ((s >> 16) as u16, 0x12, outer_stack));
    {
        let state = runtime.win16.as_ref().unwrap();
        let pointer = state.selectors.pointer_from_raw(Selector(runtime.cpu.regs.ss), outer_stack).unwrap();
        let mut bytes = [0; 14];
        state.selectors.read(&runtime.memory, pointer, &mut bytes).unwrap();
        assert_eq!(bytes, outer_bytes, "nested Pascal cleanup must preserve the outer callback frame");
    }
    return_saved_procedure(&mut runtime, &mut host, 0xfedc_1234);
    assert_eq!((runtime.cpu.regs.cs, runtime.cpu.regs.ip(), runtime.cpu.regs.sp()),
        (caller.0, 0x12, caller.1));
    let state = runtime.win16.as_ref().unwrap();
    assert!(state.window_callbacks.is_empty());
    assert!(state.window_operations.is_empty());
    assert_class_roots(&runtime, &[p, n]);
    assert_window_roots(&runtime, &[p, s]);
}

#[test]
fn class_data_procedure_invalid_far_targets_leave_class_window_and_history_unchanged() {
    let mut runtime = fixture();
    let mut host = ClassDataHost::default();
    let class = named_class(&mut runtime, &mut host, b"Invalid", 0);
    let hwnd = window(&mut runtime, class, 1);
    let p = class.info.lpfn_wnd_proc;
    let s = procedure(&runtime, 0x40);
    assert_eq!(call(&mut runtime, &mut host, 136, hwnd, GWL_WNDPROC, Some(s)), p);
    let state = runtime.win16.as_mut().unwrap();
    let short_code = state.selectors.alloc_block(PhysAddr(0x88000), 4,
        AccessRights::code(), &runtime.memory).unwrap();
    let native = state.native_procedure_gate(Win16HostProcedure(0x1234_5678_9abc_def0), &mut runtime.memory).unwrap();
    assert_ne!(native, 0);
    let ole_callback = state.ole1_client_callback_gate(&mut runtime.memory).unwrap();
    let ole_method = state.ole1_object_method_gate(1, 0, &mut runtime.memory).unwrap();
    let mut invalid = vec![0, 0xffff_0000, u32::from(runtime.cpu.regs.ds) << 16,
        (u32::from(short_code.raw().0) << 16) | 4, native + 3,
        ole_callback, ole_method];
    for target in [ole_callback, ole_method] {
        for alias in 0..8_u32 {
            invalid.push((target & !0x0007_0000) | (alias << 16));
        }
    }
    for selector in [state.gate_selector.0, state.callback_gate_selector.0] {
        for alias in 0..8_u16 { invalid.push(u32::from((selector & !7) | alias) << 16); }
    }
    for replacement in invalid {
        assert_eq!(call(&mut runtime, &mut host, 132, hwnd, GCL_WNDPROC, Some(replacement)), 0,
            "invalid target 0x{replacement:08x}");
        assert_eq!(call(&mut runtime, &mut host, 131, hwnd, GCL_WNDPROC, None), p);
        assert_eq!(call(&mut runtime, &mut host, 135, hwnd, GWL_WNDPROC, None), s);
        assert_class_roots(&runtime, &[p]);
        assert_window_roots(&runtime, &[p]);
    }
    assert_eq!(host.registrations.len(), 1);
    assert!(host.unregistrations.is_empty());
}


#[test]
fn class_data_procedure_stale_native_gate_generation_cannot_be_reused_as_guest_code() {
    let mut runtime = fixture();
    let mut host = ClassDataHost::default();
    let class = named_class(&mut runtime, &mut host, b"StaleGate", 0);
    let hwnd = window(&mut runtime, class, 1);
    let state = runtime.win16.as_mut().unwrap();
    let gate = state.native_procedure_gate(Win16HostProcedure(0x2345_6789_abcd_ef01),
        &mut runtime.memory).unwrap();
    let reference = state.selectors.reference(Selector((gate >> 16) as u16)).unwrap();
    let descriptor = state.selectors.describe(reference).unwrap();
    state.selectors.free_selector(reference).unwrap();
    assert_eq!(state.native_procedure_for_address(gate), None);
    assert_eq!(call(&mut runtime, &mut host, 132, hwnd, GCL_WNDPROC, Some(gate)), 0);
    let state = runtime.win16.as_mut().unwrap();
    let replacement = state.selectors.alloc_block(descriptor.base, descriptor.limit + 1,
        AccessRights::code(), &runtime.memory).unwrap();
    assert_eq!(replacement.raw().0, reference.raw().0, "reuse the stale raw gate selector");
    let pointer = state.selectors.pointer_from_far(gate).unwrap();
    state.selectors.translate(pointer, Access::Execute, 1, &runtime.memory).unwrap();
    assert_eq!(state.native_procedure_for_address(gate), None,
        "matching raw executable bits do not revive a retired gate generation");
    assert_eq!(call(&mut runtime, &mut host, 132, hwnd, GCL_WNDPROC, Some(gate)), 0);
    assert_eq!(call(&mut runtime, &mut host, 131, hwnd, GCL_WNDPROC, None), class.info.lpfn_wnd_proc);
    assert_eq!(call(&mut runtime, &mut host, 135, hwnd, GWL_WNDPROC, None), class.info.lpfn_wnd_proc);
    assert_class_roots(&runtime, &[class.info.lpfn_wnd_proc]);
    assert_window_roots(&runtime, &[]);
}

#[test]
fn class_data_procedure_rejects_inconsistent_selected_window_identity_without_mutation() {
    for mismatch in 0..5 {
        let mut runtime = fixture();
        let mut host = ClassDataHost::default();
        let class = named_class(&mut runtime, &mut host, b"Identity", 0);
        let hwnd = window(&mut runtime, class, 1);
        let p = class.info.lpfn_wnd_proc;
        let s = procedure(&runtime, 0x40);
        let n = procedure(&runtime, 0x60);
        assert_eq!(call(&mut runtime, &mut host, 136, hwnd, GWL_WNDPROC, Some(s)), p);
        let state = runtime.win16.as_mut().unwrap();
        match mismatch {
            0 => { state.window_procedures.remove(&hwnd); }
            1 => { state.window_procedures.get_mut(&hwnd).unwrap().class = Win16HostClass(0x9876); }
            2 => { state.window_procedures.get_mut(&hwnd).unwrap().instance ^= 1; }
            3 => { state.window_handles.insert(hwnd, Win16HostWindow(0xfedc_9999)); }
            4 => { state.window_system_classes.insert(hwnd, Win16HostSystemClass::Button); }
            _ => unreachable!(),
        }
        let previous = state.window_procedures.get(&hwnd).copied();
        assert_eq!(call(&mut runtime, &mut host, 132, hwnd, GCL_WNDPROC, Some(n)), 0,
            "inconsistent selected HWND case {mismatch}");
        let state = runtime.win16.as_ref().unwrap();
        assert!(state.window_procedures.get(&hwnd).copied() == previous);
        assert_eq!(state.window_classes.guest_class_info(class.class).unwrap().1.lpfn_wnd_proc, p);
        assert_class_roots(&runtime, &[p]);
        assert_window_roots(&runtime, &[p]);
        assert_eq!(host.registrations.len(), 1);
        assert!(host.unregistrations.is_empty());
    }
}

#[test]
fn class_data_procedure_accepts_published_native_wndproc_gate_and_its_selector_aliases() {
    let mut runtime = fixture();
    let mut host = ClassDataHost::default();
    let class = named_class(&mut runtime, &mut host, b"NativeGate", 0);
    let hwnd = window(&mut runtime, class, 1);
    let state = runtime.win16.as_mut().unwrap();
    let token = Win16HostProcedure(0x1234_5678_9abc_def0);
    let gate = state.native_procedure_gate(token, &mut runtime.memory).unwrap();
    assert_ne!(gate, 0);
    let mut old = class.info.lpfn_wnd_proc;
    for low_bits in 0..8_u32 {
        let alias = (gate & !0x0007_0000) | (low_bits << 16);
        assert_eq!(runtime.win16.as_ref().unwrap().native_procedure_for_address(alias), Some(token));
        assert_eq!(call(&mut runtime, &mut host, 132, hwnd, GCL_WNDPROC, Some(alias)), old);
        assert_eq!(call(&mut runtime, &mut host, 131, hwnd, GCL_WNDPROC, None), alias);
        assert_eq!(call(&mut runtime, &mut host, 135, hwnd, GWL_WNDPROC, None), alias);
        old = alias;
    }
    assert!(host.diagnostics.is_empty());
}

#[test]
fn class_data_procedure_histories_survive_last_window_and_failed_unregister_until_retry() {
    for failure in [HostResult::Refused, HostResult::Error] {
        let mut runtime = fixture();
        let mut host = ClassDataHost::default();
        let class = named_class(&mut runtime, &mut host, b"RetainedHistory", 4);
        let hwnd = window(&mut runtime, class, 1);
        let p = class.info.lpfn_wnd_proc;
        let s = procedure(&runtime, 0x40);
        let n = procedure(&runtime, 0x60);
        assert_eq!(call(&mut runtime, &mut host, 136, hwnd, GWL_WNDPROC, Some(s)), p);
        assert_eq!(call(&mut runtime, &mut host, 132, hwnd, GCL_WNDPROC, Some(n)), p);
        assert_eq!(call(&mut runtime, &mut host, 132, hwnd, 0, Some(0x9876_5432)), 0);
        let state = runtime.win16.as_mut().unwrap();
        assert_eq!(state.unregister_class(class.info.h_instance,
            Win16ClassName::Atom(class.atom), &mut host).unwrap(), 0);
        assert!(host.unregistrations.is_empty());
        state.retire_window_handle(hwnd).unwrap();
        assert_window_roots(&runtime, &[]);
        assert_class_roots(&runtime, &[p, n]);
        host.unregistration_result = failure;
        let state = runtime.win16.as_mut().unwrap();
        let result = state.unregister_class(class.info.h_instance,
            Win16ClassName::Atom(class.atom), &mut host);
        match failure {
            HostResult::Refused => assert_eq!(result.unwrap(), 0),
            HostResult::Error => assert_eq!(result.unwrap_err().kind(), Kind::HostFailure),
            HostResult::Success => unreachable!(),
        }
        assert!(state.is_registered_class_atom(class.atom));
        assert_eq!(state.window_classes.guest_class_info(class.class).unwrap().1.lpfn_wnd_proc, n);
        assert_eq!(state.window_classes.guest_class_extra_mut(class.class).unwrap(),
            &0x9876_5432_u32.to_le_bytes());
        assert_class_roots(&runtime, &[p, n]);
        host.unregistration_result = HostResult::Success;
        assert_eq!(runtime.win16.as_mut().unwrap().unregister_class(class.info.h_instance,
            Win16ClassName::Atom(class.atom), &mut host).unwrap(), 1);
        assert_class_roots(&runtime, &[]);
        assert_eq!(host.unregistrations, vec![class.class, class.class]);
        let fresh = named_class(&mut runtime, &mut host, b"RetainedHistory", 4);
        assert_ne!(fresh.atom, class.atom);
        assert_class_roots(&runtime, &[fresh.info.lpfn_wnd_proc]);
        let fresh_hwnd = future_window(&mut runtime, &mut host, fresh, 2);
        assert_eq!(call(&mut runtime, &mut host, 131, fresh_hwnd, 0, None), 0);
    }
}

// Separate real executable allocations make class-history and per-HWND roots
// observable to the normal FreeLibrary/safe-point reaper. The main module owns
// the registration, so it does not accidentally root either code-only module.
fn code_module(runtime: &mut Runtime) -> (u16, u32) {
    let mut donor = fixture();
    let donor_state = donor.win16.as_mut().unwrap();
    let mut module = donor_state.modules.records.remove(&donor_state.modules.main).unwrap();
    let state = runtime.win16.as_mut().unwrap();
    let header = ModuleAllocation::allocate(&mut state.heap, &mut state.selectors,
        &mut runtime.memory, 64, false).unwrap();
    let code = ModuleAllocation::allocate(&mut state.heap, &mut state.selectors,
        &mut runtime.memory, 256, true).unwrap();
    let handle = header.selector.raw().0;
    let address = (u32::from(code.selector.raw().0) << 16) | 0x20;
    module.handle = handle;
    module.instance = handle;
    module.loaded = None;
    module.definition = None;
    module.allocations = vec![header, code];
    module.deps.clear();
    module.pinned = false;
    module.explicit_refs = 1;
    module.continuation_owner_refs = 0;
    module.state = ModuleState::Ready;
    state.modules.records.insert(handle, module);
    (handle, address)
}

fn reap(runtime: &mut Runtime, host: &mut ClassDataHost) {
    let state = runtime.win16.as_mut().unwrap();
    state.module_reap_pending = true;
    state.reap_modules(&mut runtime.cpu, &mut runtime.dos, &mut runtime.memory, host).unwrap();
}

#[test]
fn class_data_procedure_old_class_code_outlives_selected_hwnd_but_displaced_subclass_does_not() {
    let mut runtime = fixture();
    let mut host = ClassDataHost::default();
    let (old_module, p) = code_module(&mut runtime);
    let (subclass_module, s) = code_module(&mut runtime);
    let mut info = class_info(&runtime, 0);
    info.lpfn_wnd_proc = p;
    let class = register(&mut runtime, &mut host, info,
        Win16ClassName::Name(b"CodeOwners".to_vec()));
    let hwnd = window(&mut runtime, class, 1);
    let n = procedure(&runtime, 0x60);
    assert_eq!(call(&mut runtime, &mut host, 136, hwnd, GWL_WNDPROC, Some(s)), p);
    assert_eq!(call(&mut runtime, &mut host, 132, hwnd, GCL_WNDPROC, Some(n)), p);
    for module in [old_module, subclass_module] {
        let return_to = (runtime.cpu.regs.cs, 0x12, u32::from(runtime.cpu.regs.sp()));
        runtime.win16.as_mut().unwrap().begin_free_library(module,
            &mut runtime.cpu, &mut runtime.dos, &mut runtime.memory, &mut host, return_to).unwrap();
    }
    reap(&mut runtime, &mut host);
    for module in [old_module, subclass_module] {
        let record = &runtime.win16.as_ref().unwrap().modules.records[&module];
        assert_eq!(record.explicit_refs, 0);
        assert_eq!(record.state, ModuleState::Ready);
    }
    runtime.win16.as_mut().unwrap().retire_window_handle(hwnd).unwrap();
    reap(&mut runtime, &mut host);
    let state = runtime.win16.as_ref().unwrap();
    assert!(state.modules.records.contains_key(&old_module), "class history must root its old code owner");
    assert!(!state.modules.records.contains_key(&subclass_module), "displaced subclass roots end with the HWND");
    let pointer = state.selectors.pointer_from_far(p).unwrap();
    state.selectors.translate(pointer, Access::Execute, 1, &runtime.memory).unwrap();
    assert!(state.selectors.pointer_from_far(s).is_err());
    assert_class_roots(&runtime, &[p, n]);
    assert_window_roots(&runtime, &[]);
    assert!(host.unregistrations.is_empty());
    host.unregistration_result = HostResult::Refused;
    assert_eq!(runtime.win16.as_mut().unwrap().unregister_class(class.info.h_instance,
        Win16ClassName::Atom(class.atom), &mut host).unwrap(), 0);
    reap(&mut runtime, &mut host);
    let state = runtime.win16.as_ref().unwrap();
    assert_eq!(state.modules.records[&old_module].state, ModuleState::Ready);
    assert!(state.is_registered_class_atom(class.atom));
    let pointer = state.selectors.pointer_from_far(p).unwrap();
    state.selectors.translate(pointer, Access::Execute, 1, &runtime.memory).unwrap();
    assert_class_roots(&runtime, &[p, n]);
    assert_eq!(host.unregistrations, vec![class.class]);
    host.unregistration_result = HostResult::Success;
    assert_eq!(runtime.win16.as_mut().unwrap().unregister_class(class.info.h_instance,
        Win16ClassName::Atom(class.atom), &mut host).unwrap(), 1);
    reap(&mut runtime, &mut host);
    let state = runtime.win16.as_ref().unwrap();
    assert!(!state.modules.records.contains_key(&old_module));
    assert!(state.selectors.pointer_from_far(p).is_err());
    assert_eq!(host.unregistrations, vec![class.class, class.class]);
}

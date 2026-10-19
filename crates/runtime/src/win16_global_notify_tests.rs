//! Real service frames and checked RETF decisions over task-owned heap blocks.
use super::*;
use crate::Runtime;
use crate::win16_runtime::{
    ImportBinding,
    execute::Win16TaskExecutionEnded,
    test_support::{NoHost, tiny_ne_executable},
};
use guest_core::{GuestMemory, Selector, io::NoPorts};
use win16_abi::global::{GMEM_DISCARDABLE, GMEM_DISCARDED, GMEM_NOTIFY};
use win16_abi::{ExportLookupTarget, lookup_export};

fn fixture() -> (Runtime, u32) {
    let mut runtime = Runtime::load(&tiny_ne_executable(), &[], br"C:\NOTIFY.NE").unwrap();
    let callback = (u32::from(runtime.cpu.regs.cs) << 16) | 0x80;
    let state = runtime.win16.as_mut().unwrap();
    let pointer = state.selectors.pointer_from_far(callback).unwrap();
    let physical = state
        .selectors
        .translate(pointer, Access::Execute, 3, &runtime.memory)
        .unwrap();
    runtime.memory.write(physical, &[0xca, 2, 0]).unwrap();
    (runtime, callback)
}

fn api(runtime: &mut Runtime, ordinal: u16, arguments: &[u8]) -> Result<(), RuntimeError> {
    let state = runtime.win16.as_mut().unwrap();
    let descriptor = lookup_export(b"KERNEL", ExportLookupTarget::Ordinal(ordinal)).unwrap();
    let mut bytes = runtime.cpu.regs.ip().to_le_bytes().to_vec();
    bytes.extend_from_slice(&runtime.cpu.regs.cs.to_le_bytes());
    bytes.extend_from_slice(arguments);
    let sp = runtime.cpu.regs.sp() - u16::try_from(bytes.len()).unwrap();
    let pointer = state
        .selectors
        .pointer_from_raw(Selector(runtime.cpu.regs.ss), sp)
        .unwrap();
    state
        .selectors
        .write(&mut runtime.memory, pointer, &bytes)
        .unwrap();
    let slot = state.bindings.len();
    state.bindings.push(ImportBinding::Supported(descriptor));
    runtime.cpu.regs.cs = state.gate_selector.0;
    runtime.cpu.regs.set_ip((slot * 2) as u16);
    runtime.cpu.regs.set_sp(sp);
    state
        .dispatch(
            &mut runtime.cpu,
            &mut runtime.memory,
            &mut runtime.dos,
            &mut NoHost,
            0,
        )
        .map(|_| ())
}

fn allocate(runtime: &mut Runtime, notify: bool) -> u16 {
    let flags = GMEM_MOVEABLE | GMEM_DISCARDABLE | if notify { GMEM_NOTIFY } else { 0 };
    let handle = runtime
        .win16
        .as_mut()
        .unwrap()
        .global_alloc(flags, 512, &mut runtime.memory, &mut NoHost)
        .unwrap();
    assert_ne!(handle, 0);
    handle
}

fn discarded(runtime: &Runtime, handle: u16) -> bool {
    runtime.win16.as_ref().unwrap().kernel_global_flags(handle) & u32::from(GMEM_DISCARDED) != 0
}

fn discard(runtime: &mut Runtime, handle: u16) {
    let mut args = GMEM_MOVEABLE.to_le_bytes().to_vec();
    args.extend_from_slice(&0_u32.to_le_bytes());
    args.extend_from_slice(&handle.to_le_bytes());
    api(runtime, 16, &args).unwrap();
}

fn parameter(runtime: &Runtime) -> u16 {
    let state = runtime.win16.as_ref().unwrap();
    let pointer = state
        .selectors
        .pointer_from_raw(Selector(runtime.cpu.regs.ss), runtime.cpu.regs.sp() + 4)
        .unwrap();
    let mut bytes = [0; 2];
    state
        .selectors
        .read(&runtime.memory, pointer, &mut bytes)
        .unwrap();
    u16::from_le_bytes(bytes)
}

fn vote(runtime: &mut Runtime, allowed: bool) {
    runtime.cpu.regs.set_ax(u16::from(allowed));
    let state = runtime.win16.as_mut().unwrap();
    let segments = crate::win16_loader::Win16Segments {
        selectors: &state.selectors,
        memory_len: runtime.memory.len(),
    };
    runtime
        .cpu
        .step_with_context(&mut runtime.memory.bus(), &mut NoPorts, &segments)
        .unwrap();
    state
        .finish_callback(
            &mut runtime.cpu,
            &mut runtime.memory,
            &mut runtime.dos,
            &mut NoHost,
        )
        .unwrap();
}

fn clean(runtime: &Runtime) {
    let state = runtime.win16.as_ref().unwrap();
    assert!(!state.global_notify.has_active_frames());
    assert!(state.callback_kinds.is_empty());
    assert!(state.legacy_cpu_frames.is_empty());
}

#[test]
fn global_notify_registration_is_void_checked_replaceable_and_clearable() {
    let (mut runtime, callback) = fixture();
    runtime.cpu.regs.set_ax(0xa55a);
    runtime.cpu.regs.set_dx(0x5aa5);
    let saved = runtime.cpu.regs.clone();
    api(&mut runtime, 154, &callback.to_le_bytes()).unwrap();
    assert_eq!(runtime.cpu.regs, saved);
    let state = runtime.win16.as_mut().unwrap();
    let owner = state.current_task_owner().unwrap();
    let pointer = state.global_notify.registrations[&owner];
    let bad = (u32::from(runtime.cpu.regs.ds) << 16) | 1;
    assert!(state.kernel_global_notify(bad, &runtime.memory).is_err());
    assert_eq!(state.global_notify.registrations[&owner], pointer);
    state
        .kernel_global_notify(callback + 1, &runtime.memory)
        .unwrap();
    assert_eq!(
        state.global_notify.registrations[&owner].far_value(),
        callback + 1
    );
    state.kernel_global_notify(0, &runtime.memory).unwrap();
    assert!(state.global_notify.registrations.is_empty());
    clean(&runtime);
}

#[test]
fn global_notify_input_policy_is_distinct_from_returned_discarded_state() {
    let (mut runtime, _) = fixture();
    let handle = allocate(&mut runtime, true);
    let state = runtime.win16.as_mut().unwrap();
    let identity = state.global_handles[&handle];
    assert!(state.heap.info(identity).unwrap().notify_on_discard);
    assert_eq!(
        state.kernel_global_flags(handle) & u32::from(GMEM_DISCARDED),
        0
    );
    state
        .kernel_global_realloc(handle, 256, GMEM_MOVEABLE, &mut runtime.memory, &mut NoHost)
        .unwrap();
    assert!(state.heap.info(identity).unwrap().notify_on_discard);
    discard(&mut runtime, handle); // No registered callback: ordinary discard.
    assert!(discarded(&runtime, handle));
    clean(&runtime);
}

#[test]
fn global_notify_discard_uses_one_word_pascal_argument_and_honors_veto() {
    for allowed in [false, true] {
        let (mut runtime, callback) = fixture();
        let handle = allocate(&mut runtime, true);
        api(&mut runtime, 154, &callback.to_le_bytes()).unwrap();
        let saved = runtime.cpu.regs.clone();
        discard(&mut runtime, handle);
        assert_eq!(runtime.cpu.regs.cs, (callback >> 16) as u16);
        assert_eq!(runtime.cpu.regs.ip(), callback as u16);
        assert_eq!(runtime.cpu.regs.ax(), runtime.cpu.regs.ss);
        assert_eq!(
            (runtime.cpu.regs.ds, runtime.cpu.regs.es),
            (runtime.cpu.regs.ss, runtime.cpu.regs.ss)
        );
        assert_eq!(parameter(&runtime), handle);
        assert!(!discarded(&runtime, handle));
        vote(&mut runtime, allowed);
        assert_eq!(discarded(&runtime, handle), allowed);
        assert_eq!(runtime.cpu.regs.ax(), if allowed { handle } else { 0 });
        assert_eq!(
            (
                runtime.cpu.regs.cs,
                runtime.cpu.regs.ip(),
                runtime.cpu.regs.sp(),
                runtime.cpu.regs.ds
            ),
            (saved.cs, saved.ip(), saved.sp(), saved.ds)
        );
        clean(&runtime);
    }
}

#[test]
fn global_notify_compaction_continues_past_a_veto_and_ignores_unmarked_blocks() {
    let (mut runtime, callback) = fixture();
    let vetoed = allocate(&mut runtime, true);
    let unmarked = allocate(&mut runtime, false);
    let accepted = allocate(&mut runtime, true);
    api(&mut runtime, 154, &callback.to_le_bytes()).unwrap();
    api(&mut runtime, 25, &u32::MAX.to_le_bytes()).unwrap();
    assert_eq!(parameter(&runtime), vetoed);
    vote(&mut runtime, false);
    assert_eq!(parameter(&runtime), accepted);
    assert!(discarded(&runtime, unmarked));
    vote(&mut runtime, true);
    assert!(!discarded(&runtime, vetoed));
    assert!(discarded(&runtime, accepted));
    clean(&runtime);
}

#[test]
fn global_notify_freed_candidate_cannot_discard_a_reused_guest_word() {
    let (mut runtime, callback) = fixture();
    let handle = allocate(&mut runtime, true);
    api(&mut runtime, 154, &callback.to_le_bytes()).unwrap();
    discard(&mut runtime, handle);
    let state = runtime.win16.as_mut().unwrap();
    let old = state.global_handles[&handle];
    assert_eq!(state.global_free(handle).unwrap(), 0);
    let replacement = allocate(&mut runtime, true);
    let state = runtime.win16.as_mut().unwrap();
    let next = state.global_handles[&replacement];
    assert_ne!(old, next);
    // Force WORD-table reuse independently of the selector allocator's cursor.
    // The old callback must reject this new allocation identity before any API.
    state.global_handles.insert(handle, next);
    vote(&mut runtime, true);
    assert_eq!(runtime.cpu.regs.ax(), 0);
    assert!(
        !runtime
            .win16
            .as_ref()
            .unwrap()
            .heap
            .info(next)
            .unwrap()
            .discarded
    );
    clean(&runtime);
}

#[test]
fn global_notify_memory_freed_is_word_arithmetic_and_stops_the_discard_pass() {
    let (mut runtime, callback) = fixture();
    api(&mut runtime, 126, &7_u16.to_le_bytes()).unwrap();
    assert_eq!((runtime.cpu.regs.ax(), runtime.cpu.regs.dx()), (0, 0));
    let first = allocate(&mut runtime, true);
    let second = allocate(&mut runtime, true);
    api(&mut runtime, 154, &callback.to_le_bytes()).unwrap();
    let minimum = runtime
        .win16
        .as_ref()
        .unwrap()
        .heap
        .maximum_available()
        .unwrap()
        + 16;
    api(&mut runtime, 25, &minimum.to_le_bytes()).unwrap();
    assert_eq!(parameter(&runtime), first);
    api(&mut runtime, 126, &0_u16.to_le_bytes()).unwrap();
    let needed = runtime.cpu.regs.ax();
    assert_ne!(needed, 0);
    api(&mut runtime, 126, &u16::MAX.to_le_bytes()).unwrap();
    assert_eq!(
        (runtime.cpu.regs.ax(), runtime.cpu.regs.dx()),
        (needed.wrapping_sub(u16::MAX), 0)
    );
    vote(&mut runtime, false);
    assert!(!discarded(&runtime, first));
    assert!(!discarded(&runtime, second));
    clean(&runtime);
}

#[test]
fn global_notify_nested_discard_decisions_restore_the_exact_outer_owner() {
    let (mut runtime, callback) = fixture();
    let first = allocate(&mut runtime, true);
    let second = allocate(&mut runtime, true);
    api(&mut runtime, 154, &callback.to_le_bytes()).unwrap();
    discard(&mut runtime, first);
    let outer_sp = runtime.cpu.regs.sp();
    discard(&mut runtime, second);
    assert_eq!(
        runtime.win16.as_ref().unwrap().global_notify.frames.len(),
        2
    );
    vote(&mut runtime, true);
    assert_eq!(runtime.cpu.regs.sp(), outer_sp);
    assert_eq!(parameter(&runtime), first);
    vote(&mut runtime, false);
    assert!(!discarded(&runtime, first));
    assert!(discarded(&runtime, second));
    clean(&runtime);
}

#[test]
fn global_notify_terminal_abort_never_commits_an_unreturned_vote() {
    let (mut runtime, callback) = fixture();
    let handle = allocate(&mut runtime, true);
    api(&mut runtime, 154, &callback.to_le_bytes()).unwrap();
    discard(&mut runtime, handle);
    let state = runtime.win16.as_mut().unwrap();
    state
        .cancel_global_notify_for_teardown(
            &Win16TaskExecutionEnded::for_test(),
            &mut runtime.cpu,
            &mut runtime.dos,
            &mut runtime.memory,
        )
        .unwrap();
    let owner = state.current_task_owner().unwrap();
    state.global_notify.retire_task(owner).unwrap();
    assert!(!discarded(&runtime, handle));
    clean(&runtime);
}

#[test]
fn global_notify_allocation_pressure_retries_after_the_real_callback() {
    let (mut runtime, callback) = fixture();
    let handle = allocate(&mut runtime, true);
    api(&mut runtime, 154, &callback.to_le_bytes()).unwrap();
    let requested = runtime
        .win16
        .as_ref()
        .unwrap()
        .heap
        .maximum_available()
        .unwrap()
        + 16;
    let mut args = requested.to_le_bytes().to_vec();
    args.extend_from_slice(&GMEM_MOVEABLE.to_le_bytes());
    api(&mut runtime, 15, &args).unwrap();
    assert_eq!(parameter(&runtime), handle);
    vote(&mut runtime, true);
    assert!(discarded(&runtime, handle));
    let result = runtime.cpu.regs.ax();
    assert_ne!(result, 0);
    assert_eq!(
        (
            runtime.cpu.regs.bx(),
            runtime.cpu.regs.cx(),
            runtime.cpu.regs.es
        ),
        (result, result, 0)
    );
    assert_eq!(
        runtime.win16.as_ref().unwrap().global_size(result).unwrap(),
        requested
    );
    clean(&runtime);
}

#[test]
fn global_notify_reallocation_pressure_retains_the_original_allocation_identity() {
    let (mut runtime, callback) = fixture();
    // Keep this growth below 64 KiB. Expanding a huge selector run next to
    // another stable HGLOBAL is a separate allocator constraint, tested below.
    let largest = runtime
        .win16
        .as_ref()
        .unwrap()
        .heap
        .maximum_available()
        .unwrap();
    let padding = runtime
        .win16
        .as_mut()
        .unwrap()
        .global_alloc(0, largest - 0x2000, &mut runtime.memory, &mut NoHost)
        .unwrap();
    assert_ne!(padding, 0);
    let growing = allocate(&mut runtime, true);
    let victim = allocate(&mut runtime, true);
    api(&mut runtime, 154, &callback.to_le_bytes()).unwrap();
    let requested = runtime
        .win16
        .as_ref()
        .unwrap()
        .heap
        .maximum_available()
        .unwrap()
        + 16;
    let mut args = GMEM_MOVEABLE.to_le_bytes().to_vec();
    args.extend_from_slice(&requested.to_le_bytes());
    args.extend_from_slice(&growing.to_le_bytes());
    api(&mut runtime, 16, &args).unwrap();
    assert_eq!(parameter(&runtime), victim);
    vote(&mut runtime, true);
    assert_eq!(runtime.cpu.regs.ax(), growing);
    assert_eq!(
        runtime
            .win16
            .as_ref()
            .unwrap()
            .global_size(growing)
            .unwrap(),
        requested
    );
    clean(&runtime);
}

#[test]
fn global_notify_immediate_resize_does_not_pin_the_callers_data_selector() {
    let (mut runtime, callback) = fixture();
    api(&mut runtime, 154, &callback.to_le_bytes()).unwrap();
    let state = runtime.win16.as_mut().unwrap();
    let handle = state
        .global_alloc(GMEM_MOVEABLE, 512, &mut runtime.memory, &mut NoHost)
        .unwrap();
    let far = state.global_lock(handle, &runtime.memory).unwrap();
    runtime.cpu.regs.ds = (far >> 16) as u16;
    let mut args = GMEM_MOVEABLE.to_le_bytes().to_vec();
    args.extend_from_slice(&1024_u32.to_le_bytes());
    args.extend_from_slice(&handle.to_le_bytes());
    api(&mut runtime, 16, &args).unwrap();
    assert_eq!(runtime.cpu.regs.ax(), handle);
    assert_eq!(
        runtime.win16.as_ref().unwrap().global_size(handle).unwrap(),
        1024
    );
    clean(&runtime);
}

#[test]
fn global_notify_huge_selector_growth_failure_keeps_the_original_data() {
    let (mut runtime, callback) = fixture();
    let growing = allocate(&mut runtime, true);
    let victim = allocate(&mut runtime, true);
    let state = runtime.win16.as_mut().unwrap();
    let far = state.global_lock(growing, &runtime.memory).unwrap();
    let pointer = state.selectors.pointer_from_far(far).unwrap();
    state
        .selectors
        .write(&mut runtime.memory, pointer, b"kept")
        .unwrap();
    state.global_unlock(growing).unwrap();
    api(&mut runtime, 154, &callback.to_le_bytes()).unwrap();
    let requested = runtime
        .win16
        .as_ref()
        .unwrap()
        .heap
        .maximum_available()
        .unwrap()
        + 16;
    let mut args = GMEM_MOVEABLE.to_le_bytes().to_vec();
    args.extend_from_slice(&requested.to_le_bytes());
    args.extend_from_slice(&growing.to_le_bytes());
    api(&mut runtime, 16, &args).unwrap();
    assert_eq!(parameter(&runtime), victim);
    vote(&mut runtime, true);
    assert_eq!(runtime.cpu.regs.ax(), 0); // Stable adjacent selectors cannot be replaced.
    assert!(discarded(&runtime, victim));
    let state = runtime.win16.as_mut().unwrap();
    assert_eq!(state.global_size(growing).unwrap(), 512);
    let far = state.global_lock(growing, &runtime.memory).unwrap();
    let pointer = state.selectors.pointer_from_far(far).unwrap();
    let mut bytes = [0; 4];
    state
        .selectors
        .read(&runtime.memory, pointer, &mut bytes)
        .unwrap();
    assert_eq!(&bytes, b"kept");
    state.global_unlock(growing).unwrap();
    clean(&runtime);
}

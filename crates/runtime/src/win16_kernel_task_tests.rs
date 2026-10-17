//! Task-handle, last-error, and version-profile checks for the KERNEL task exports.

use super::super::{
    ImportBinding, WIN16_MEMORY_END,
    test_support::{NoHost, tiny_ne_executable},
};
use crate::{DiagnosticKind, Runtime, RuntimeError};
use guest_core::{PhysAddr, Selector};
use win16_abi::{AccessRights, ExportLookupTarget, WINDOWS_COMPATIBILITY_PROFILE, lookup_export};

fn fixture() -> (Runtime, u16) {
    let runtime = Runtime::load(&tiny_ne_executable(), &[], br"C:\TASK.NE").unwrap();
    let stack = runtime.cpu.regs.sp();
    (runtime, stack)
}

fn pascal_words(words: &[u16]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for word in words.iter().rev() {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    bytes
}

fn invoke(
    runtime: &mut Runtime,
    stack_sp: u16,
    ordinal: u16,
    args: &[u8],
) -> Result<(u16, u16), RuntimeError> {
    let descriptor = lookup_export(b"KERNEL", ExportLookupTarget::Ordinal(ordinal)).unwrap();
    runtime.cpu.regs.set_sp(stack_sp);
    runtime.cpu.regs.set_ax(0xA55A);
    runtime.cpu.regs.set_dx(0xBEEF);
    let return_cs = runtime.cpu.regs.cs;
    let return_ip = 0x12_u16;
    let mut bytes = return_ip.to_le_bytes().to_vec();
    bytes.extend_from_slice(&return_cs.to_le_bytes());
    bytes.extend_from_slice(args);
    let state = runtime.win16.as_mut().unwrap();
    let stack = state
        .selectors
        .pointer_from_raw(Selector(runtime.cpu.regs.ss), runtime.cpu.regs.sp())
        .unwrap();
    state
        .selectors
        .write(&mut runtime.memory, stack, &bytes)
        .unwrap();
    let slot = state.bindings.len();
    state.bindings.push(ImportBinding::Supported(descriptor));
    runtime.cpu.regs.cs = state.gate_selector.0;
    runtime.cpu.regs.set_ip((slot * 2) as u16);
    runtime.win16.as_mut().unwrap().dispatch(
        &mut runtime.cpu,
        &mut runtime.memory,
        &mut runtime.dos,
        &mut NoHost,
        0,
    )?;
    Ok((runtime.cpu.regs.ax(), runtime.cpu.regs.dx()))
}

fn current_handle(runtime: &Runtime) -> u16 {
    runtime
        .win16
        .as_ref()
        .unwrap()
        .current_task_handle()
        .unwrap()
}

#[test]
fn task_handles_follow_get_current_task() {
    let (mut runtime, stack) = fixture();
    let state = runtime.win16.as_ref().unwrap();
    let current = state.current_task_handle().unwrap();
    let first = state.first_task_handle;
    let instance = state.instance_selector.raw().0;
    let owner = state.tasks.current().unwrap();

    let (ax, dx) = invoke(&mut runtime, stack, 36, &[]).unwrap();
    assert_eq!(ax, current);
    assert_eq!(dx, first);
    assert_eq!(current_handle(&runtime), current);

    let (locked, preserved) = invoke(&mut runtime, stack, 33, &pascal_words(&[1])).unwrap();
    assert_eq!(locked, current);
    assert_eq!(preserved, 0xBEEF);
    let (still_locked, _) = invoke(&mut runtime, stack, 122, &[]).unwrap();
    assert_eq!(still_locked, current);

    let (unlocked, _) = invoke(&mut runtime, stack, 33, &pascal_words(&[0])).unwrap();
    assert_eq!(unlocked, 0);
    let (not_locked, _) = invoke(&mut runtime, stack, 122, &[]).unwrap();
    assert_eq!(not_locked, 0);

    let (previous, _) = invoke(&mut runtime, stack, 34, &pascal_words(&[0, 0x1234])).unwrap();
    assert_eq!(previous, 0);
    let (queue, _) = invoke(&mut runtime, stack, 35, &pascal_words(&[current])).unwrap();
    assert_eq!(queue, 0x1234);
    let (missing, _) = invoke(&mut runtime, stack, 35, &pascal_words(&[0xBEEF])).unwrap();
    assert_eq!(missing, 0);
    assert_eq!(current_handle(&runtime), current);

    runtime.cpu.regs.ds = instance;
    runtime.cpu.regs.es = 0xBEEF;
    let (from_ds, _) = invoke(&mut runtime, stack, 118, &[]).unwrap();
    assert_eq!(from_ds, 0x1234);
    assert_eq!(runtime.cpu.regs.ds, instance);
    let (from_es, _) = invoke(&mut runtime, stack, 119, &[]).unwrap();
    assert_eq!(from_es, 0);
    assert_eq!(runtime.cpu.regs.es, 0xBEEF);

    runtime.cpu.regs.ds = current;
    let (from_task_ds, _) = invoke(&mut runtime, stack, 118, &[]).unwrap();
    assert_eq!(from_task_ds, 0x1234);

    let state = runtime.win16.as_ref().unwrap();
    assert_eq!(state.task_controls.queue.get(&owner).copied(), Some(0x1234));
    assert_eq!(state.tasks.current(), Some(owner));
}

#[test]
fn last_error_and_version_ex_follow_the_get_version_profile() {
    let (mut runtime, stack) = fixture();
    let (ax, dx) = invoke(&mut runtime, stack, 148, &[]).unwrap();
    assert_eq!((dx, ax), (0, 0));

    let error = 0x8007_0005_u32;
    let (preserved_ax, preserved_dx) =
        invoke(&mut runtime, stack, 147, &error.to_le_bytes()).unwrap();
    assert_eq!((preserved_ax, preserved_dx), (0xA55A, 0xBEEF));
    let (ax, dx) = invoke(&mut runtime, stack, 148, &[]).unwrap();
    assert_eq!(((u32::from(dx) << 16) | u32::from(ax)), error);

    let (version_ax, version_dx) = invoke(&mut runtime, stack, 3, &[]).unwrap();
    assert_eq!(version_ax, WINDOWS_COMPATIBILITY_PROFILE.version_word());
    assert_eq!(
        u32::from(version_dx) << 16 | u32::from(version_ax),
        0x0500_0A03
    );

    let state = runtime.win16.as_mut().unwrap();
    let selector = state
        .selectors
        .alloc_block(
            PhysAddr(WIN16_MEMORY_END - 0x2000),
            0x100,
            AccessRights::read_write(),
            &runtime.memory,
        )
        .unwrap();
    let pointer = state.selectors.pointer_from_raw(selector.raw(), 0).unwrap();
    state
        .selectors
        .write(&mut runtime.memory, pointer, &[0x5A; 0x100])
        .unwrap();
    let far = u32::from(selector.raw().0) << 16;

    let (failed, _) = invoke(&mut runtime, stack, 149, &0_u32.to_le_bytes()).unwrap();
    assert_eq!(failed, 0);
    let (wrong_size, _) = invoke(&mut runtime, stack, 149, &far.to_le_bytes()).unwrap();
    assert_eq!(wrong_size, 0);
    let mut unchanged = [0_u8; 8];
    runtime
        .win16
        .as_ref()
        .unwrap()
        .selectors
        .read(&runtime.memory, pointer, &mut unchanged)
        .unwrap();
    assert_eq!(unchanged, [0x5A; 8]);

    runtime
        .win16
        .as_ref()
        .unwrap()
        .selectors
        .write(&mut runtime.memory, pointer, &148_u32.to_le_bytes())
        .unwrap();
    let (ok, preserved) = invoke(&mut runtime, stack, 149, &far.to_le_bytes()).unwrap();
    assert_eq!(ok, 1);
    assert_eq!(preserved, 0xBEEF);
    let mut info = [0_u8; 148];
    runtime
        .win16
        .as_ref()
        .unwrap()
        .selectors
        .read(&runtime.memory, pointer, &mut info)
        .unwrap();
    assert_eq!(u32::from_le_bytes(info[0..4].try_into().unwrap()), 148);
    assert_eq!(
        u32::from_le_bytes(info[4..8].try_into().unwrap()),
        u32::from(version_ax & 0xFF)
    );
    assert_eq!(
        u32::from_le_bytes(info[8..12].try_into().unwrap()),
        u32::from(version_ax >> 8)
    );
    assert_eq!(u32::from_le_bytes(info[12..16].try_into().unwrap()), 0);
    assert_eq!(u32::from_le_bytes(info[16..20].try_into().unwrap()), 0);
    assert!(info[20..].iter().all(|byte| *byte == 0));
    let (still, _) = invoke(&mut runtime, stack, 148, &[]).unwrap();
    assert_eq!(still, 0x0005);
}

#[test]
fn directed_yield_returns_task_switch_failure_without_switching() {
    let (mut runtime, stack) = fixture();
    let current = current_handle(&runtime);
    let owner = runtime.win16.as_ref().unwrap().tasks.current().unwrap();
    for target in [0_u16, current, 0xBEEF] {
        let (failed, preserved) =
            invoke(&mut runtime, stack, 150, &pascal_words(&[target])).unwrap();
        assert_eq!(failed, 0);
        assert_eq!(preserved, 0xBEEF);
        assert_eq!(current_handle(&runtime), current);
        assert_eq!(runtime.win16.as_ref().unwrap().tasks.current(), Some(owner));
    }
}

#[test]
fn set_priority_clamps_and_leaves_the_current_task_in_place() {
    let (mut runtime, stack) = fixture();
    let current = current_handle(&runtime);
    let owner = runtime.win16.as_ref().unwrap().tasks.current().unwrap();
    let (ax, dx) = invoke(
        &mut runtime,
        stack,
        32,
        &pascal_words(&[0, (-100_i16) as u16]),
    )
    .unwrap();
    assert_eq!((ax, dx), (0xA55A, 0xBEEF));
    assert_eq!(
        runtime
            .win16
            .as_ref()
            .unwrap()
            .task_controls
            .priority
            .get(&owner)
            .copied(),
        Some(-32),
    );
    invoke(&mut runtime, stack, 32, &pascal_words(&[current, 100])).unwrap();
    assert_eq!(
        runtime
            .win16
            .as_ref()
            .unwrap()
            .task_controls
            .priority
            .get(&owner)
            .copied(),
        Some(15),
    );
    invoke(&mut runtime, stack, 32, &pascal_words(&[0xBEEF, 1])).unwrap();
    assert_eq!(
        runtime
            .win16
            .as_ref()
            .unwrap()
            .task_controls
            .priority
            .get(&owner)
            .copied(),
        Some(15),
    );
    assert_eq!(current_handle(&runtime), current);
}

#[test]
fn old_yield_asks_the_host_thread_and_does_not_switch() {
    let (mut runtime, stack) = fixture();
    let current = current_handle(&runtime);
    let owner = runtime.win16.as_ref().unwrap().tasks.current().unwrap();
    let error = invoke(&mut runtime, stack, 117, &[]).unwrap_err();
    assert_eq!(error.kind(), DiagnosticKind::CompatibilityGap);
    assert_eq!(current_handle(&runtime), current);
    assert_eq!(runtime.win16.as_ref().unwrap().tasks.current(), Some(owner));
}

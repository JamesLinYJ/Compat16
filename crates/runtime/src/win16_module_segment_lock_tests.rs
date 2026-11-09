//! Protected-mode GlobalLock and GlobalFlags on module segments.
//!
//! KB Q61285: GlobalLock counts discardable objects and the default data
//! segment. A movable segment that is neither is not counted. Fixed memory
//! that is not counted stays nonzero from GlobalUnlock.

use super::super::module_memory::ModuleAllocation;
use super::super::module_registry::{ModuleRecord, ModuleState};
use super::super::test_support::{NoHost, tiny_ne_executable};
use super::super::ImportBinding;
use super::*;
use crate::Runtime;
use guest_core::Selector;
use win16_abi::{ExportLookupTarget, lookup_export};

const GMEM_DISCARDABLE_FLAG: u16 = GMEM_DISCARDABLE;

fn fixture_image(image: &[u8]) -> Runtime {
    Runtime::load(image, &[], br"C:\SEGLOCK.NE").unwrap()
}

fn stock() -> Runtime {
    fixture_image(&tiny_ne_executable())
}

fn segment_selector(runtime: &Runtime, number: u16) -> u16 {
    runtime.win16.as_ref().unwrap().loaded.segments.iter()
        .find(|segment| segment.number == number)
        .unwrap()
        .selector.0
}

fn data_bytes(runtime: &Runtime) -> [u8; 8] {
    let state = runtime.win16.as_ref().unwrap();
    let selector = segment_selector(runtime, 2);
    let pointer = state.selectors.pointer_from_raw(Selector(selector), 0).unwrap();
    let mut bytes = [0; 8];
    state.selectors.read(&runtime.memory, pointer, &mut bytes).unwrap();
    bytes
}

fn call(runtime: &mut Runtime, ordinal: u16, handle: u16) -> (u16, u16) {
    runtime.cpu.regs.set_sp(0x80);
    let return_to = (runtime.cpu.regs.cs, runtime.cpu.regs.ip(), 0x86_u16);
    let state = runtime.win16.as_mut().unwrap();
    let mut bytes = Vec::from(return_to.1.to_le_bytes());
    bytes.extend_from_slice(&return_to.0.to_le_bytes());
    bytes.extend_from_slice(&handle.to_le_bytes());
    let pointer = state.selectors.pointer_from_raw(Selector(runtime.cpu.regs.ss), 0x80).unwrap();
    state.selectors.write(&mut runtime.memory, pointer, &bytes).unwrap();
    let slot = state.bindings.len();
    state.bindings.push(ImportBinding::Supported(
        lookup_export(b"KERNEL", ExportLookupTarget::Ordinal(ordinal)).unwrap(),
    ));
    runtime.cpu.regs.cs = state.gate_selector.0;
    runtime.cpu.regs.set_ip((slot * 2) as u16);
    runtime.cpu.regs.set_ax(0);
    runtime.cpu.regs.set_dx(0);
    state.dispatch(&mut runtime.cpu, &mut runtime.memory, &mut runtime.dos, &mut NoHost, 0).unwrap();
    (runtime.cpu.regs.ax(), runtime.cpu.regs.dx())
}

#[test]
fn get_code_handle_names_the_task_code_segment() {
    let mut runtime = stock();
    let code = segment_selector(&runtime, 1);
    let data = segment_selector(&runtime, 2);
    let state = runtime.win16.as_mut().unwrap();
    let expected = state.loaded_segment_handles[&code];
    let procedure = u32::from(code) << 16;
    assert_eq!(state.kernel_get_code_handle(procedure, &runtime.memory), u32::from(expected));
    assert_eq!(state.kernel_get_code_handle(u32::from(data) << 16, &runtime.memory), 0);

    let output = u32::from(data) << 16;
    let pointer = state.selectors.pointer_from_raw(Selector(data), 0).unwrap();
    state.selectors.write(&mut runtime.memory, pointer, &[0xA5; 16]).unwrap();
    state.kernel_get_code_info(0, output, &mut runtime.memory).unwrap();
    let mut unchanged = [0; 16];
    state.selectors.read(&runtime.memory, pointer, &mut unchanged).unwrap();
    assert_eq!(unchanged, [0xA5; 16]);

    state.kernel_get_code_info(procedure, output, &mut runtime.memory).unwrap();
    let mut info = [0; 16];
    state.selectors.read(&runtime.memory, pointer, &mut info).unwrap();
    let handle = u16::from_le_bytes([info[8], info[9]]);
    let flags = u16::from_le_bytes([info[4], info[5]]);
    let allocated = u16::from_le_bytes([info[6], info[7]]);
    assert_eq!(handle, expected);
    assert_eq!(flags, 0);
    assert_eq!(u32::from(allocated), state.loaded.segments.iter()
        .find(|segment| segment.number == 1).unwrap().memory_size);
    assert_eq!(state.global_lock(handle, &runtime.memory).unwrap(), procedure);
    assert_eq!(state.kernel_global_flags(handle), 0);
}

#[test]
fn global_lock_counts_dgroup_and_ignores_fixed_code_and_module_header() {
    let mut runtime = stock();
    let before = data_bytes(&runtime);
    let instance = runtime.win16.as_ref().unwrap().instance_handle;
    let module = runtime.win16.as_ref().unwrap().modules.main;
    let data = segment_selector(&runtime, 2);
    let code = segment_selector(&runtime, 1);
    assert_eq!(instance, data);

    let state = runtime.win16.as_mut().unwrap();
    assert_eq!(state.kernel_global_flags(instance), 0);
    assert_eq!(state.kernel_global_flags(module), 0);
    assert_eq!(state.kernel_global_flags(code), 0);
    assert_eq!(state.kernel_global_flags(0xBEEF), u32::from(GMEM_INVALID_HANDLE));

    let locked = state.global_lock(instance, &runtime.memory).unwrap();
    assert_eq!(locked, u32::from(data) << 16);
    assert_eq!(state.kernel_global_flags(instance), 1);
    assert_eq!(state.kernel_global_flags(data), 1);
    assert_eq!(state.global_lock(data, &runtime.memory).unwrap(), locked);
    assert_eq!(state.kernel_global_flags(instance), 2);
    assert_eq!(state.global_unlock(instance).unwrap(), 1);
    assert_eq!(state.global_unlock(data).unwrap(), 0);
    assert_eq!(state.kernel_global_flags(instance), 0);
    assert_eq!(state.global_unlock(instance).unwrap(), 0);

    assert_ne!(state.global_lock(code, &runtime.memory).unwrap(), 0);
    assert_eq!(state.kernel_global_flags(code), 0);
    assert_eq!(state.global_unlock(code).unwrap(), 1);
    assert_eq!(state.global_unlock(code).unwrap(), 1);

    let header = state.global_lock(module, &runtime.memory).unwrap();
    assert_ne!(header, 0);
    assert_ne!(header >> 16, u32::from(data));
    assert_eq!(state.kernel_global_flags(module), 0);
    assert_eq!(state.global_unlock(module).unwrap(), 1);
    assert_eq!(data_bytes(&runtime), before);
}

#[test]
fn global_lock_service_returns_dgroup_selector_and_flag_word() {
    let mut runtime = stock();
    let data = segment_selector(&runtime, 2);
    assert_eq!(call(&mut runtime, 18, data), (0, data));
    assert_eq!(call(&mut runtime, 22, data), (1, 0));
    assert_eq!(call(&mut runtime, 19, data), (0, 0));
    assert_eq!(call(&mut runtime, 22, data), (0, 0));
    assert_eq!(call(&mut runtime, 22, 0xBEEF), (GMEM_INVALID_HANDLE, 0));
}

#[test]
fn movable_nondiscardable_code_segment_does_not_count() {
    let mut image = tiny_ne_executable();
    image[0x84..0x86].copy_from_slice(&NE_SEGMENT_MOVEABLE.to_le_bytes());
    let mut runtime = fixture_image(&image);
    let selector = segment_selector(&runtime, 1);
    let state = runtime.win16.as_mut().unwrap();
    let handle = state.loaded_segment_handles[&selector];
    assert_eq!(handle, selector - 1);
    assert_eq!(state.kernel_global_flags(handle), 0);
    assert_eq!(state.global_lock(handle, &runtime.memory).unwrap(), u32::from(selector) << 16);
    assert_eq!(state.kernel_global_flags(selector), 0);
    assert_eq!(state.global_unlock(handle).unwrap(), 0);
    assert!(state.module_segment_locks.get(&selector).is_none());
}

#[test]
fn discardable_code_segment_counts_and_reports_discardable() {
    let mut image = tiny_ne_executable();
    let flags = NE_SEGMENT_MOVEABLE | NE_SEGMENT_DISCARDABLE;
    image[0x84..0x86].copy_from_slice(&flags.to_le_bytes());
    let mut runtime = fixture_image(&image);
    let selector = segment_selector(&runtime, 1);
    let state = runtime.win16.as_mut().unwrap();
    let handle = state.loaded_segment_handles[&selector];
    assert_eq!(state.kernel_global_flags(handle), u32::from(GMEM_DISCARDABLE_FLAG));
    assert_ne!(state.global_lock(handle, &runtime.memory).unwrap(), 0);
    assert_eq!(state.kernel_global_flags(selector), u32::from(GMEM_DISCARDABLE_FLAG) | 1);
    assert_eq!(state.global_unlock(handle).unwrap(), 0);
    assert_eq!(state.kernel_global_flags(handle), u32::from(GMEM_DISCARDABLE_FLAG));
    assert!(state.module_segment_locks.get(&selector).is_none());
}

#[test]
fn module_segment_lock_count_saturates_without_wrapping() {
    let mut runtime = stock();
    let data = segment_selector(&runtime, 2);
    let state = runtime.win16.as_mut().unwrap();
    state.module_segment_locks.insert(data, u16::MAX);
    assert_eq!(state.global_lock(data, &runtime.memory).unwrap(), 0);
    assert_eq!(state.module_segment_locks[&data], u16::MAX);
    assert_eq!(state.kernel_global_flags(data) & 0xff, 0xff);
}

#[test]
fn heap_backed_discardable_segment_counts_on_its_block() {
    let mut runtime = stock();
    let state = runtime.win16.as_mut().unwrap();
    let header = ModuleAllocation::allocate(
        &mut state.heap, &mut state.selectors, &mut runtime.memory, 64, false,
    ).unwrap();
    let segment = ModuleAllocation::allocate(
        &mut state.heap, &mut state.selectors, &mut runtime.memory, 128, true,
    ).unwrap();
    let selector = segment.selector.raw().0;
    let guest_handle = selector - 1;
    let mut definition = state.modules.records[&state.modules.main].definition.clone().unwrap();
    definition.header.automatic_data_segment = 0;
    definition.segments.iter_mut().find(|segment| segment.number == 1).unwrap().flags =
        NE_SEGMENT_MOVEABLE | NE_SEGMENT_DISCARDABLE;
    let mut loaded = state.modules.records[&state.modules.main].loaded.clone().unwrap();
    loaded.segments.retain(|segment| segment.number == 1);
    loaded.segments[0].selector = segment.selector.raw();
    loaded.segments[0].memory_size = 128;
    let module_handle = header.selector.raw().0;
    let identity = segment.handle;
    state.loaded_segment_handles.insert(selector, guest_handle);
    state.modules.records.insert(module_handle, ModuleRecord {
        handle: module_handle,
        instance: module_handle,
        path: b"LOCKSEG.DLL".to_vec(),
        name: b"LOCKSEG".to_vec(),
        builtin: false,
        pinned: false,
        explicit_refs: 1,
        continuation_owner_refs: 0,
        state: ModuleState::Ready,
        deps: Vec::new(),
        definition: Some(definition),
        loaded: Some(loaded),
        image: Vec::new(),
        allocations: vec![header, segment],
        builtin_data_selector: None,
        builtin_data_exports: None,
        external_application: None,
        wep_called: false,
        resources_retirement_deferred: false,
    });

    assert_eq!(state.kernel_global_flags(guest_handle), u32::from(GMEM_DISCARDABLE_FLAG));
    assert_eq!(state.heap.info(identity).unwrap().lock_count, 0);
    assert_eq!(
        state.global_lock(guest_handle, &runtime.memory).unwrap(),
        u32::from(selector) << 16,
    );
    assert_eq!(state.heap.info(identity).unwrap().lock_count, 1);
    state.modules.records.get_mut(&module_handle).unwrap().state = ModuleState::Retired;
    assert_eq!(
        state.kernel_global_flags(selector),
        u32::from(GMEM_DISCARDABLE_FLAG) | 1,
    );
    assert_eq!(state.global_unlock(selector).unwrap(), 0);
    assert_eq!(state.heap.info(identity).unwrap().lock_count, 0);
    assert_eq!(state.kernel_global_flags(guest_handle), u32::from(GMEM_DISCARDABLE_FLAG));

    let plain = state.global_alloc(GMEM_MOVEABLE, 16, &mut runtime.memory, &mut NoHost).unwrap();
    assert_ne!(state.global_lock(plain, &runtime.memory).unwrap(), 0);
    assert_eq!(state.kernel_global_flags(plain) & 0xff, 0);
}

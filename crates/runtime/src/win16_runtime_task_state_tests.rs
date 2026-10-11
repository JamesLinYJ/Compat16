//! PostEvent target ownership, guest-memory publication, and failure ordering.

use std::{cell::{Cell, RefCell}, rc::Rc};

use super::*;
use super::super::{ImportBinding, test_support::{NoHost, tiny_ne_executable}, WIN16_MEMORY_END};
use crate::Runtime;
use guest_core::{OwnerId, PhysAddr, MemoryError, io::NoPorts, memory::MemoryStorage};
use win16_abi::{AccessRights, AllocationFlags, ExportLookupTarget, SelectorRef, TaskDatabase,
    TASK_DATABASE_PREFIX_SIZE, Win16ExportId, Win16ReturnKind, lookup_export};

const SECOND: OwnerId = OwnerId(2);
const SECOND_BASE: u32 = WIN16_MEMORY_END - 0x1000;

fn fixture() -> Runtime {
    Runtime::load(&tiny_ne_executable(), &[], br"C:\EVENT.NE").unwrap()
}

fn add_task(runtime: &mut Runtime, rights: AccessRights, size: u32) -> SelectorRef {
    let state = runtime.win16.as_mut().unwrap();
    let current = state.tasks.current().unwrap();
    state.tasks.create(SECOND, Some(current)).unwrap();
    let selector = state.selectors.alloc_block(PhysAddr(SECOND_BASE), size, rights,
        &runtime.memory).unwrap();
    state.runtime_arena_backing.register_chunk(RuntimeArenaChunkKind::TaskDatabase,
        selector, &state.selectors, &runtime.memory).unwrap();
    state.task_handles.insert(SECOND, selector.raw().0);
    let mut database = TaskDatabase::new();
    database.set_hself(selector.raw().0);
    runtime.memory.write(PhysAddr(SECOND_BASE), database.as_bytes()).unwrap();
    selector
}

fn count(runtime: &Runtime, handle: u16) -> u16 {
    let state = runtime.win16.as_ref().unwrap();
    let pointer = state.selectors.pointer_from_raw(Selector(handle), TASK_EVENT_COUNT_OFFSET as u16).unwrap();
    let mut bytes = [0; 2];
    state.selectors.read(&runtime.memory, pointer, &mut bytes).unwrap();
    u16::from_le_bytes(bytes)
}

fn prepare_gate(runtime: &mut Runtime, target: u16) -> (u16, u16, u16) {
    let descriptor = lookup_export(b"KERNEL", ExportLookupTarget::Ordinal(31)).unwrap();
    assert_eq!(descriptor.id, Win16ExportId::KernelPostEvent);
    assert_eq!(descriptor.return_kind, Win16ReturnKind::Void);
    let return_to = (runtime.cpu.regs.cs, 0x12_u16, runtime.cpu.regs.sp() + 6);
    let mut bytes = return_to.1.to_le_bytes().to_vec();
    bytes.extend_from_slice(&return_to.0.to_le_bytes());
    bytes.extend_from_slice(&target.to_le_bytes());
    let state = runtime.win16.as_mut().unwrap();
    let stack = state.selectors.pointer_from_raw(Selector(runtime.cpu.regs.ss), runtime.cpu.regs.sp()).unwrap();
    state.selectors.write(&mut runtime.memory, stack, &bytes).unwrap();
    let slot = state.bindings.len();
    state.bindings.push(ImportBinding::Supported(descriptor));
    runtime.cpu.regs.cs = state.gate_selector.0;
    runtime.cpu.regs.set_ip((slot * 2) as u16);
    runtime.cpu.regs.eax = 0x1357_a55a;
    runtime.cpu.regs.edx = 0x2468_5aa5;
    return_to
}

fn dispatch(runtime: &mut Runtime) -> Result<Option<u8>, RuntimeError> {
    runtime.win16.as_mut().unwrap().dispatch(&mut runtime.cpu, &mut runtime.memory,
        &mut runtime.dos, &mut NoHost, 0)
}

#[test]
fn post_event_zero_and_explicit_current_preserve_existing_void_return_and_cleanup() {
    for explicit in [false, true] {
        let mut runtime = fixture();
        let state = runtime.win16.as_ref().unwrap();
        let handle = state.current_task_handle().unwrap();
        let owner = state.tasks.current().unwrap();
        assert_eq!(count(&runtime, handle), 1);
        let return_to = prepare_gate(&mut runtime, if explicit { handle } else { 0 });
        let mut expected = runtime.cpu.regs.clone();
        expected.cs = return_to.0;
        expected.set_ip(return_to.1);
        expected.set_sp(return_to.2);
        assert_eq!(dispatch(&mut runtime).unwrap(), None);
        assert_eq!(runtime.cpu.regs, expected);
        assert_eq!(runtime.win16.as_ref().unwrap().tasks.pending_events(owner).unwrap(), 2);
        assert_eq!(count(&runtime, handle), 2);
    }
}

#[test]
fn post_event_routes_to_ready_or_suspended_task_without_scheduling_and_guest_reads_count() {
    for suspended in [false, true] {
        let mut runtime = fixture();
        let target = add_task(&mut runtime, AccessRights::read_write(), TASK_DATABASE_PREFIX_SIZE as u32);
        let state = runtime.win16.as_mut().unwrap();
        let current = state.tasks.current().unwrap();
        let current_handle = state.current_task_handle().unwrap();
        if suspended {
            state.tasks.dispatch(SECOND).unwrap();
            state.tasks.suspend(SECOND).unwrap();
            state.tasks.dispatch(current).unwrap();
        }
        let target_state = state.tasks.info(SECOND).unwrap();
        let current_state = state.tasks.info(current).unwrap();
        let return_to = prepare_gate(&mut runtime, target.raw().0);
        dispatch(&mut runtime).unwrap();
        let state = runtime.win16.as_ref().unwrap();
        assert_eq!(state.tasks.info(SECOND).unwrap(), target_state);
        assert_eq!(state.tasks.info(current).unwrap(), current_state);
        assert_eq!(state.tasks.current(), Some(current));
        assert_eq!(state.tasks.pending_events(SECOND).unwrap(), 1);
        assert_eq!(state.tasks.pending_events(current).unwrap(), 1);
        assert_eq!(count(&runtime, target.raw().0), 1);
        assert_eq!(count(&runtime, current_handle), 1);

        // Execute MOV AX,ES:[0006] against the target TDB, not a Rust-only view.
        let code = state.selectors.pointer_from_raw(Selector(return_to.0), return_to.1).unwrap();
        let physical = state.selectors.translate(code, Access::Execute, 4, &runtime.memory).unwrap();
        runtime.memory.write(physical, &[0x26, 0xa1, 6, 0]).unwrap();
        runtime.cpu.regs.es = target.raw().0;
        runtime.cpu.regs.set_ax(0xbeef);
        let segments = crate::win16_loader::Win16Segments {
            selectors: &state.selectors, memory_len: runtime.memory.len(),
        };
        runtime.cpu.step_with_context(&mut runtime.memory.bus(), &mut NoPorts, &segments).unwrap();
        assert_eq!(runtime.cpu.regs.ax(), 1);
    }
}

#[test]
fn post_event_rejects_unknown_or_unregistered_selector_without_guest_return() {
    for mapped in [false, true] {
        let mut runtime = fixture();
        let state = runtime.win16.as_mut().unwrap();
        let current = state.tasks.current().unwrap();
        let current_handle = state.current_task_handle().unwrap();
        let target = if mapped {
            let alias = state.selectors.alloc_cs_to_ds_alias(state.instance_selector, &runtime.memory).unwrap();
            state.tasks.create(SECOND, Some(current)).unwrap();
            state.task_handles.insert(SECOND, alias.raw().0);
            alias.raw().0
        } else { 0xfff7 };
        prepare_gate(&mut runtime, target);
        let before = runtime.cpu.regs.clone();
        assert_eq!(dispatch(&mut runtime).unwrap_err().kind(), Kind::GuestFault);
        assert_eq!(runtime.cpu.regs, before);
        assert_eq!(runtime.win16.as_ref().unwrap().tasks.pending_events(current).unwrap(), 1);
        assert_eq!(count(&runtime, current_handle), 1);
        if mapped {
            assert_eq!(runtime.win16.as_ref().unwrap().tasks.pending_events(SECOND).unwrap(), 0);
        }
    }
}

#[test]
fn post_event_rejects_retired_tasks_and_reused_tdb_selector_generation() {
    for case in 0..3 {
        let mut runtime = fixture();
        let target = add_task(&mut runtime, AccessRights::read_write(), TASK_DATABASE_PREFIX_SIZE as u32);
        let state = runtime.win16.as_mut().unwrap();
        if case == 0 {
            state.selectors.free_block(target).unwrap();
            let replacement = state.selectors.alloc_block(PhysAddr(SECOND_BASE),
                TASK_DATABASE_PREFIX_SIZE as u32, AccessRights::read_write(), &runtime.memory).unwrap();
            assert_eq!(replacement.raw(), target.raw());
            assert_ne!(replacement.generation(), target.generation());
        } else if case == 1 {
            state.tasks.terminate(SECOND, 0, &mut state.heap, &mut state.selectors).unwrap();
            assert_eq!(state.tasks.info(SECOND).unwrap().state, TaskState::Exited);
        } else {
            // An owned stale selector makes cleanup fail after the registry
            // has moved the target into its non-dispatchable Terminating state.
            let allocation = state.heap.alloc(&mut runtime.memory, SECOND, 16,
                AllocationFlags::movable()).unwrap();
            let pointer = state.heap.lock(allocation, &mut state.selectors, &runtime.memory).unwrap();
            state.selectors.free_block(pointer.selector()).unwrap();
            assert!(state.tasks.terminate(SECOND, 0, &mut state.heap, &mut state.selectors).is_err());
            assert_eq!(state.tasks.info(SECOND).unwrap().state, TaskState::Terminating);
        }
        prepare_gate(&mut runtime, target.raw().0);
        let before = runtime.cpu.regs.clone();
        assert_eq!(dispatch(&mut runtime).unwrap_err().kind(), Kind::GuestFault);
        assert_eq!(runtime.cpu.regs, before);
        assert_eq!(runtime.win16.as_ref().unwrap().tasks.pending_events(SECOND).unwrap(), 0);
        assert_eq!(count(&runtime, target.raw().0), 0);
    }
}

#[test]
fn post_event_preflights_target_write_before_incrementing_registry() {
    for (rights, size) in [(AccessRights::read_only(), TASK_DATABASE_PREFIX_SIZE as u32),
        (AccessRights::read_write(), TASK_EVENT_COUNT_OFFSET as u32 + 1)] {
        let mut runtime = fixture();
        let target = add_task(&mut runtime, rights, size);
        prepare_gate(&mut runtime, target.raw().0);
        let before = runtime.cpu.regs.clone();
        assert_eq!(dispatch(&mut runtime).unwrap_err().kind(), Kind::GuestFault);
        assert_eq!(runtime.cpu.regs, before);
        assert_eq!(runtime.win16.as_ref().unwrap().tasks.pending_events(SECOND).unwrap(), 0);
        let mut bytes = [0; 2];
        runtime.memory.read(PhysAddr(SECOND_BASE + TASK_EVENT_COUNT_OFFSET as u32), &mut bytes).unwrap();
        assert_eq!(bytes, [0, 0]);
    }
}

#[test]
fn post_event_preserves_existing_saturation_policy_in_registry_and_tdb() {
    let mut runtime = fixture();
    let state = runtime.win16.as_mut().unwrap();
    let owner = state.tasks.current().unwrap();
    let handle = state.current_task_handle().unwrap();
    for _ in 1..u16::MAX { state.tasks.post_event(owner).unwrap(); }
    state.sync_task_event_count(&mut runtime.memory).unwrap();
    prepare_gate(&mut runtime, handle);
    dispatch(&mut runtime).unwrap();
    assert_eq!(runtime.win16.as_ref().unwrap().tasks.pending_events(owner).unwrap(), u16::MAX);
    assert_eq!(count(&runtime, handle), u16::MAX);
}

struct FailingStorage {
    bytes: Rc<RefCell<Vec<u8>>>,
    failure_address: Rc<Cell<Option<u32>>>,
    failed_writes: Rc<Cell<u32>>,
}

impl MemoryStorage for FailingStorage {
    fn len(&self) -> u32 { self.bytes.borrow().len() as u32 }
    fn read(&self, offset: u32, output: &mut [u8]) -> Result<(), MemoryError> {
        output.copy_from_slice(&self.bytes.borrow()[offset as usize..offset as usize + output.len()]);
        Ok(())
    }
    fn write(&mut self, offset: u32, input: &[u8]) -> Result<(), MemoryError> {
        if self.failure_address.get() == Some(offset) {
            self.failed_writes.set(self.failed_writes.get() + 1);
            self.bytes.borrow_mut()[offset as usize] = input[0];
            return Err(MemoryError::StorageAccess {
                address: offset, length: input.len(), transferred: 1, write: true, os_error: None,
            });
        }
        self.bytes.borrow_mut()[offset as usize..offset as usize + input.len()].copy_from_slice(input);
        Ok(())
    }
}

#[test]
fn post_event_partial_storage_failure_stops_without_registry_commit_or_rollback() {
    let image = tiny_ne_executable();
    let bytes = Rc::new(RefCell::new(vec![0; Runtime::memory_size_for_image(&image) as usize]));
    let failure_address = Rc::new(Cell::new(None));
    let failed_writes = Rc::new(Cell::new(0));
    let store = FailingStorage { bytes: bytes.clone(), failure_address: failure_address.clone(),
        failed_writes: failed_writes.clone() };
    let mut runtime = Runtime::load_with_storage(&image, &[], br"C:\EVENT.NE", br"C:\EVENT.NE",
        &[], Some(Box::new(store))).unwrap();
    let state = runtime.win16.as_mut().unwrap();
    let owner = state.tasks.current().unwrap();
    let handle = state.current_task_handle().unwrap();
    // 00ff -> 0100 makes a one-byte partial write observable as 0000.
    for _ in 1..0xff { state.tasks.post_event(owner).unwrap(); }
    state.sync_task_event_count(&mut runtime.memory).unwrap();
    let pointer = state.selectors.pointer_from_raw(Selector(handle), TASK_EVENT_COUNT_OFFSET as u16).unwrap();
    let address = state.selectors.translate(pointer, Access::Write, 2, &runtime.memory).unwrap();
    prepare_gate(&mut runtime, handle);
    let before = runtime.cpu.regs.clone();
    failure_address.set(Some(address.0));
    assert_eq!(dispatch(&mut runtime).unwrap_err().kind(), Kind::HostFailure);
    assert_eq!(runtime.cpu.regs, before);
    assert_eq!(runtime.win16.as_ref().unwrap().tasks.pending_events(owner).unwrap(), 0xff);
    assert_eq!(&bytes.borrow()[address.0 as usize..address.0 as usize + 2], &[0, 0]);
    assert_eq!(failed_writes.get(), 1);
    assert!(matches!(runtime.memory.storage_failure(), Some(MemoryError::StorageAccess {
        transferred: 1, write: true, ..
    })));
    // Poisoned storage rejects later access without replaying the backend write.
    assert!(runtime.memory.write(address, &[0xff, 0]).is_err());
    assert_eq!(failed_writes.get(), 1);
}

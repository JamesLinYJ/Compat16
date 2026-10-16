//! USER.224 service gate, immutable queue ownership, and stale identity rejection.

use super::*;
use super::super::{ImportBinding, test_support::{NoHost, tiny_ne_executable}, WIN16_MEMORY_END};
use crate::{Runtime, Win16HostTaskQueue, Win16HostWindow};
use devices::{keyboard::KeyStroke, video::ConsoleSnapshot};
use dos_kernel::{DosDirectoryEntry, DosFileAccess, DosFileSharing, DosHost, DosHostError,
    DosHostFile, DosHostSearch, DosSeekOrigin};
use guest_core::{OwnerId, PhysAddr, Selector};
use win16_abi::{AccessRights, AllocationFlags, ExportLookupTarget, SelectorRef,
    TASK_DATABASE_PREFIX_SIZE, lookup_export};

const GUEST: u16 = 0x4321;
const NATIVE: Win16HostWindow = Win16HostWindow(0x1234_5678_8765_4321);
const QUEUE: Win16HostTaskQueue = Win16HostTaskQueue(0x9876_5432_1234_5678);
const SECOND: OwnerId = OwnerId(2);
const SECOND_BASE: u32 = WIN16_MEMORY_END - 0x1000;

struct WindowTaskHost {
    reply: Reply,
    queries: Vec<Query>,
    fail: bool,
}
impl Default for WindowTaskHost {
    fn default() -> Self {
        Self { reply: Reply::TaskQueue(Some(QUEUE)), queries: Vec::new(), fail: false }
    }
}

impl DosHost for WindowTaskHost {
    fn read_stdin(&mut self, _output: &mut [u8]) -> Result<usize, DosHostError> { panic!("unexpected host call") }
    fn try_read_stdin(&mut self) -> Result<Option<u8>, DosHostError> { panic!("unexpected host call") }
    fn write_stdout(&mut self, _input: &[u8]) -> Result<usize, DosHostError> { panic!("unexpected host call") }
    fn write_stderr(&mut self, _input: &[u8]) -> Result<usize, DosHostError> { panic!("unexpected host call") }
    fn flush_stdin(&mut self) -> Result<(), DosHostError> { panic!("unexpected host call") }
    fn file_create(&mut self, _path: &[u8], _attributes: u8) -> Result<DosHostFile, DosHostError> { panic!("unexpected host call") }
    fn file_open(&mut self, _path: &[u8], _access: DosFileAccess) -> Result<DosHostFile, DosHostError> { panic!("unexpected host call") }
    fn file_open_with_sharing(&mut self, _path: &[u8], _access: DosFileAccess, _sharing: DosFileSharing) -> Result<DosHostFile, DosHostError> { panic!("unexpected host call") }
    fn file_duplicate(&mut self, _file: DosHostFile) -> Result<DosHostFile, DosHostError> { panic!("unexpected host call") }
    fn file_close(&mut self, _file: DosHostFile) -> Result<(), DosHostError> { panic!("unexpected host call") }
    fn file_read(&mut self, _file: DosHostFile, _output: &mut [u8]) -> Result<usize, DosHostError> { panic!("unexpected host call") }
    fn file_write(&mut self, _file: DosHostFile, _input: &[u8]) -> Result<usize, DosHostError> { panic!("unexpected host call") }
    fn file_seek(&mut self, _file: DosHostFile, _offset: i32, _origin: DosSeekOrigin) -> Result<u32, DosHostError> { panic!("unexpected host call") }
    fn file_set_len(&mut self, _file: DosHostFile, _length: u32) -> Result<(), DosHostError> { panic!("unexpected host call") }
    fn file_delete(&mut self, _path: &[u8]) -> Result<(), DosHostError> { panic!("unexpected host call") }
    fn directory_create(&mut self, _path: &[u8]) -> Result<(), DosHostError> { panic!("unexpected host call") }
    fn directory_remove(&mut self, _path: &[u8]) -> Result<(), DosHostError> { panic!("unexpected host call") }
    fn directory_set_current(&mut self, _path: &[u8]) -> Result<(), DosHostError> { panic!("unexpected host call") }
    fn directory_get_current(&mut self, _drive: u8, _output: &mut [u8]) -> Result<usize, DosHostError> { panic!("unexpected host call") }
    fn file_rename(&mut self, _old_path: &[u8], _new_path: &[u8]) -> Result<(), DosHostError> { panic!("unexpected host call") }
    fn file_get_attributes(&mut self, _path: &[u8]) -> Result<u8, DosHostError> { panic!("unexpected host call") }
    fn file_set_attributes(&mut self, _path: &[u8], _attributes: u8) -> Result<(), DosHostError> { panic!("unexpected host call") }
    fn directory_search_open(&mut self, _directory: &[u8]) -> Result<DosHostSearch, DosHostError> { panic!("unexpected host call") }
    fn directory_search_next(&mut self, _search: DosHostSearch) -> Result<Option<DosDirectoryEntry>, DosHostError> { panic!("unexpected host call") }
    fn directory_search_close(&mut self, _search: DosHostSearch) -> Result<(), DosHostError> { panic!("unexpected host call") }
    fn guest_code_page(&self) -> text_codec::CodePage { panic!("unexpected host call") }
    fn current_drive(&self) -> u8 { panic!("unexpected host call") }
    fn select_drive(&mut self, _drive: u8) -> Result<(), DosHostError> { panic!("unexpected host call") }
    fn logical_drive_count(&self) -> u8 { panic!("unexpected host call") }
}

impl RuntimeHost for WindowTaskHost {
    fn win16_window_enumeration(&mut self, query: Query) -> Result<Reply, RuntimeError> {
        self.queries.push(query);
        if self.fail { return Err(RuntimeError::new(Kind::HostFailure, "test window queue failure")); }
        Ok(self.reply.clone())
    }
    fn win16_initialize_user_queue(&mut self) -> Result<(), RuntimeError> {
        panic!("GetWindowTask must not create or bind a USER queue")
    }

    fn epoch_seconds(&self) -> i64 { panic!("unexpected host call") }
    fn read_bios_key(&mut self) -> Result<KeyStroke, RuntimeError> { panic!("unexpected host call") }
    fn render_text(&mut self, _screen: &ConsoleSnapshot) -> Result<(), RuntimeError> { panic!("unexpected host call") }
}

impl crate::RuntimeDdeHost for WindowTaskHost {
    fn win16_dde_abort(&mut self) -> crate::Win16DdeAbortReceipt { panic!("unexpected host call") }
}

impl crate::RuntimeMciHost for WindowTaskHost {}
impl crate::RuntimeMidiHost for WindowTaskHost {}
impl crate::RuntimeNetbiosHost for WindowTaskHost {}

fn fixture() -> Runtime {
    // Reuse the existing service-gate fixture; do not generate another NE image.
    let mut runtime = Runtime::load(&tiny_ne_executable(), &[], br"C:\WTASK.NE").unwrap();
    let state = runtime.win16.as_mut().unwrap();
    let owner = state.tasks.current().unwrap();
    let task = state.current_task_handle().unwrap();
    let generation = state.selectors.reference(Selector(task)).unwrap().generation();
    state.user_task_queue = Some((owner, task, generation, QUEUE));
    state.window_handles.insert(GUEST, NATIVE);
    runtime
}

fn add_task(runtime: &mut Runtime) -> SelectorRef {
    let state = runtime.win16.as_mut().unwrap();
    let current = state.tasks.current().unwrap();
    state.tasks.create(SECOND, Some(current)).unwrap();
    let selector = state.selectors.alloc_block(PhysAddr(SECOND_BASE),
        TASK_DATABASE_PREFIX_SIZE as u32, AccessRights::read_write(), &runtime.memory).unwrap();
    state.runtime_arena_backing.register_chunk(RuntimeArenaChunkKind::TaskDatabase,
        selector, &state.selectors, &runtime.memory).unwrap();
    state.task_handles.insert(SECOND, selector.raw().0);
    selector
}

fn prepare_gate(runtime: &mut Runtime, window: u16) -> (u16, u16, u16) {
    let return_to = (runtime.cpu.regs.cs, 0x12_u16, runtime.cpu.regs.sp() + 6);
    let mut bytes = return_to.1.to_le_bytes().to_vec();
    bytes.extend_from_slice(&return_to.0.to_le_bytes());
    bytes.extend_from_slice(&window.to_le_bytes());
    bytes.extend_from_slice(&[0xa1, 0xb2]);
    let state = runtime.win16.as_mut().unwrap();
    let pointer = state.selectors.pointer_from_raw(Selector(runtime.cpu.regs.ss), runtime.cpu.regs.sp()).unwrap();
    state.selectors.write(&mut runtime.memory, pointer, &bytes).unwrap();
    let slot = state.bindings.len();
    state.bindings.push(ImportBinding::Supported(
        lookup_export(b"USER", ExportLookupTarget::Ordinal(224)).unwrap()));
    runtime.cpu.regs.cs = state.gate_selector.0;
    runtime.cpu.regs.set_ip((slot * 2) as u16);
    runtime.cpu.regs.eax = 0x1357_a55a;
    runtime.cpu.regs.edx = 0x2468_5aa5;
    return_to
}

fn dispatch(runtime: &mut Runtime, host: &mut impl RuntimeHost) -> Result<Option<u8>, RuntimeError> {
    runtime.win16.as_mut().unwrap().dispatch(&mut runtime.cpu, &mut runtime.memory,
        &mut runtime.dos, host, 0)
}

fn query(runtime: &Runtime, window: u16, host: &mut impl RuntimeHost) -> Result<u16, RuntimeError> {
    runtime.win16.as_ref().unwrap().get_window_task(window, &runtime.memory, host)
}

#[test]
fn get_window_task_gate_returns_bound_owner_for_owned_and_borrowed_aliases() {
    for (owned, suspended) in [(false, false), (true, false), (false, true), (true, true)] {
        let mut runtime = fixture();
        add_task(&mut runtime);
        let state = runtime.win16.as_mut().unwrap();
        let bound = state.user_task_queue.unwrap();
        if owned { state.owned_window_handles.insert(GUEST); }
        // Scheduling a different task cannot change the creator queue owner.
        if suspended { state.tasks.suspend(bound.0).unwrap(); }
        state.tasks.dispatch(SECOND).unwrap();
        let other = state.current_task_handle().unwrap();
        assert_ne!(other, bound.1);
        let return_to = prepare_gate(&mut runtime, GUEST);
        let mut expected = runtime.cpu.regs.clone();
        expected.cs = return_to.0;
        expected.set_ip(return_to.1);
        expected.set_sp(return_to.2);
        expected.set_ax(bound.1);
        let mut host = WindowTaskHost::default();
        assert_eq!(dispatch(&mut runtime, &mut host).unwrap(), None);
        assert_eq!(runtime.cpu.regs, expected);
        assert_eq!(host.queries, [Query::TaskQueue(NATIVE)]);
        let state = runtime.win16.as_ref().unwrap();
        assert_eq!(state.tasks.current(), Some(SECOND));
        assert_eq!(state.user_task_queue, Some(bound));
        assert_eq!(state.window_handles[&GUEST], NATIVE);
        assert_eq!(state.owned_window_handles.contains(&GUEST), owned);
        let pointer = state.selectors.pointer_from_raw(Selector(runtime.cpu.regs.ss), return_to.2).unwrap();
        let mut sentinel = [0; 2];
        state.selectors.read(&runtime.memory, pointer, &mut sentinel).unwrap();
        assert_eq!(sentinel, [0xa1, 0xb2]);
    }
}

#[test]
fn get_window_task_unknown_windows_or_unbound_tasks_return_null_without_host_calls() {
    let runtime = fixture();
    for window in [0, 1, 0xfffe, u16::MAX, GUEST + 1] {
        assert_eq!(query(&runtime, window, &mut NoHost).unwrap(), 0);
    }
    for case in 0..6 {
        let mut runtime = fixture();
        let state = runtime.win16.as_mut().unwrap();
        let (owner, task, generation, queue) = state.user_task_queue.unwrap();
        match case {
            0 => state.user_task_queue = None,
            1 => { state.task_handles.remove(&owner); },
            2 => state.user_task_queue = Some((OwnerId(999), task, generation, queue)),
            3 => state.user_task_queue = Some((owner, task, generation + 1, queue)),
            4 => state.user_task_queue = Some((owner, 0, generation, queue)),
            _ => {
                // A live selector with a matching generation is insufficient
                // when it is not the retained task-database allocation.
                let selector = state.instance_selector;
                state.task_handles.insert(owner, selector.raw().0);
                state.user_task_queue = Some((owner, selector.raw().0,
                    selector.generation(), queue));
            }
        }
        assert_eq!(query(&runtime, GUEST, &mut NoHost).unwrap(), 0);
    }
}

#[test]
fn get_window_task_foreign_retired_or_different_queue_returns_null_without_rebinding() {
    for reply in [None, Some(Win16HostTaskQueue(QUEUE.0 + 1))] {
        let mut runtime = fixture();
        let before = runtime.win16.as_ref().unwrap().user_task_queue;
        let return_to = prepare_gate(&mut runtime, GUEST);
        let mut host = WindowTaskHost { reply: Reply::TaskQueue(reply), ..Default::default() };
        dispatch(&mut runtime, &mut host).unwrap();
        assert_eq!(runtime.cpu.regs.ax(), 0);
        assert_eq!(runtime.cpu.regs.dx(), 0x5aa5);
        assert_eq!(runtime.cpu.regs.sp(), return_to.2);
        assert_eq!(runtime.win16.as_ref().unwrap().user_task_queue, before);
        assert_eq!(host.queries, [Query::TaskQueue(NATIVE)]);
    }
}

#[test]
fn get_window_task_rejects_exited_terminating_and_reused_task_database() {
    for case in 0..5 {
        let mut runtime = fixture();
        let selector = add_task(&mut runtime);
        let state = runtime.win16.as_mut().unwrap();
        state.user_task_queue = Some((SECOND, selector.raw().0, selector.generation(), QUEUE));
        if case < 2 {
            state.selectors.free_block(selector).unwrap();
            if case == 1 {
                let replacement = state.selectors.alloc_block(PhysAddr(SECOND_BASE),
                    TASK_DATABASE_PREFIX_SIZE as u32, AccessRights::read_write(), &runtime.memory).unwrap();
                assert_eq!(replacement.raw(), selector.raw());
                assert_ne!(replacement.generation(), selector.generation());
            }
        } else if case == 2 {
            state.tasks.terminate(SECOND, 0, &mut state.heap, &mut state.selectors).unwrap();
            assert_eq!(state.tasks.info(SECOND).unwrap().state, TaskState::Exited);
        } else if case == 3 {
            let allocation = state.heap.alloc(&mut runtime.memory, SECOND, 16,
                AllocationFlags::movable()).unwrap();
            let pointer = state.heap.lock(allocation, &mut state.selectors, &runtime.memory).unwrap();
            state.selectors.free_block(pointer.selector()).unwrap();
            assert!(state.tasks.terminate(SECOND, 0, &mut state.heap, &mut state.selectors).is_err());
            assert_eq!(state.tasks.info(SECOND).unwrap().state, TaskState::Terminating);
        } else {
            state.selectors.set_selector_base(selector, PhysAddr(SECOND_BASE + 0x100),
                &runtime.memory).unwrap();
            assert_eq!(state.selectors.reference(selector.raw()).unwrap(), selector,
                "descriptor mutation preserves raw handle and generation");
        }
        assert_eq!(query(&runtime, GUEST, &mut NoHost).unwrap(), 0);
    }
}

#[test]
fn get_window_task_host_failures_leave_gate_and_ownership_unchanged() {
    for fail in [false, true] {
        let mut runtime = fixture();
        let binding = runtime.win16.as_ref().unwrap().user_task_queue;
        prepare_gate(&mut runtime, GUEST);
        let registers = runtime.cpu.regs.clone();
        let mut host = WindowTaskHost { reply: Reply::IsCurrent(true), fail, ..Default::default() };
        let expected = if fail { Kind::HostFailure } else { Kind::InternalInvariant };
        assert_eq!(dispatch(&mut runtime, &mut host).unwrap_err().kind(), expected);
        assert_eq!(runtime.cpu.regs, registers);
        let state = runtime.win16.as_ref().unwrap();
        assert_eq!(state.user_task_queue, binding);
        assert_eq!(state.window_handles[&GUEST], NATIVE);
        assert_eq!(host.queries, [Query::TaskQueue(NATIVE)]);
    }
}

#[test]
fn get_window_task_retired_and_reused_guest_window_never_reuses_old_lookup() {
    let mut runtime = fixture();
    let task = runtime.win16.as_ref().unwrap().current_task_handle().unwrap();
    let mut host = WindowTaskHost::default();
    assert_eq!(query(&runtime, GUEST, &mut host).unwrap(), task);
    runtime.win16.as_mut().unwrap().retire_window_handle(GUEST).unwrap();
    assert_eq!(query(&runtime, GUEST, &mut NoHost).unwrap(), 0);
    let replacement = Win16HostWindow(NATIVE.0 + 1);
    runtime.win16.as_mut().unwrap().window_handles.insert(GUEST, replacement);
    host.reply = Reply::TaskQueue(None);
    assert_eq!(query(&runtime, GUEST, &mut host).unwrap(), 0);
    assert_eq!(host.queries, [Query::TaskQueue(NATIVE), Query::TaskQueue(replacement)]);
    host.reply = Reply::TaskQueue(Some(QUEUE));
    assert_eq!(query(&runtime, GUEST, &mut host).unwrap(), task);
    assert_eq!(host.queries.last(), Some(&Query::TaskQueue(replacement)));
}

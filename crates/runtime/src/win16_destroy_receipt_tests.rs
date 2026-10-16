//! Mock-backed USER.53 DestroyWindow coverage for exact native retirement receipts.

use super::{ImportBinding, test_support::tiny_ne_executable};
use crate::{
    DiagnosticKind as Kind, Runtime, RuntimeError, RuntimeHost, Win16HostMenu,
    Win16HostWindow, Win16HostWindowOperationId, Win16HostWindowRetirementBatch,
    Win16HostWindowRetirementReceipt, Win16NativeWindowOperationKind,
    Win16NativeWindowOperationProof, Win16NativeWindowOperationState, Win16WindowCall,
    Win16WindowCallResult, Win16WindowOperation, Win16WindowResult,
    Win16WindowSourceRetiredProof, Win16WindowStep, Win16WindowTarget,
};
use devices::{keyboard::KeyStroke, video::ConsoleSnapshot};
use dos_kernel::{
    DosDirectoryEntry, DosFileAccess, DosFileSharing, DosHost, DosHostError,
    DosHostFile, DosHostSearch, DosSeekOrigin,
};
use guest_core::{GuestMemory, Selector};
use std::sync::Arc;
use win16_abi::{ExportLookupTarget, lookup_export};

const AX: u16 = 0xa55a;
const DX: u16 = 0x5aa5;
const ROOT_GUEST: u16 = 0x1234;
const POPUP_GUEST: u16 = 0x1235;
const CHILD_GUEST: u16 = 0x1236;
const ALIAS_GUEST: u16 = 0x2345;
const ROOT: Win16HostWindow = Win16HostWindow(0x1234_5678_9abc);
const POPUP: Win16HostWindow = Win16HostWindow(0x1234_5678_9abd);
const CHILD: Win16HostWindow = Win16HostWindow(0x1234_5678_9abe);
const REPLACEMENT: Win16HostWindow = Win16HostWindow(0x1234_5678_9abf);
const MENU: Win16HostMenu = Win16HostMenu(0x2234_5678_9abc);

struct DestroyReceiptHost {
    calls: Vec<Win16WindowTarget>,
    result: Option<Win16WindowCallResult>,
    consumed: usize,
    fail_readback_once: bool,
}

impl DestroyReceiptHost {
    fn new(succeeded: bool, windows: &[Win16HostWindow], menus: &[Win16HostMenu]) -> Self {
        Self {
            calls: Vec::new(),
            result: Some(Win16WindowCallResult::Destroyed {
                succeeded,
                retirements: Win16HostWindowRetirementBatch {
                    receipts: windows.iter().copied()
                        .map(|window| Win16HostWindowRetirementReceipt { window }).collect(),
                    invalidated_menus: menus.to_vec(),
                },
            }),
            consumed: 0,
            fail_readback_once: false,
        }
    }
}

fn proof() -> Arc<Win16WindowSourceRetiredProof> {
    Arc::new(Win16WindowSourceRetiredProof {
        operation: Win16NativeWindowOperationProof {
            operation_id: Win16HostWindowOperationId(53),
            kind: Win16NativeWindowOperationKind::WindowCall,
        },
        worker_generation: 7,
        state: Win16NativeWindowOperationState::Returned,
    })
}

impl DosHost for DestroyReceiptHost {
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

impl RuntimeHost for DestroyReceiptHost {
    fn win16_window_begin(&mut self, operation: Win16WindowOperation)
        -> Result<Win16WindowStep, RuntimeError>
    {
        let Win16WindowOperation::WindowCall(Win16WindowCall::DestroyWindow { window }) = operation
            else { panic!("unexpected host operation"); };
        self.calls.push(window);
        let proof = proof();
        Ok(Win16WindowStep::Started {
            operation_id: proof.operation.operation_id,
            worker_generation: proof.worker_generation,
            kind: proof.operation.kind,
            step: Box::new(Win16WindowStep::SourceRetired {
                proof,
                result: Box::new(Win16WindowStep::Complete(Win16WindowResult::WindowCall(
                    self.result.take().expect("DestroyWindow may begin only once"),
                ))),
            }),
        })
    }
    fn win16_window_resume(&mut self, _reply: Option<crate::Win16WindowReply>)
        -> Result<Win16WindowStep, RuntimeError>
    {
        panic!("cached DestroyWindow completion must not resume native execution")
    }
    fn win16_window_source_retirement(
        &mut self, operation: Win16NativeWindowOperationProof, worker_generation: u64,
    ) -> Result<Option<Arc<Win16WindowSourceRetiredProof>>, RuntimeError> {
        let proof = proof();
        assert_eq!(operation, proof.operation);
        assert_eq!(worker_generation, proof.worker_generation);
        if std::mem::take(&mut self.fail_readback_once) {
            return Err(RuntimeError::new(Kind::HostFailure,
                "test defers DestroyWindow source readback"));
        }
        Ok(Some(proof))
    }
    fn win16_window_source_retirement_consumed(&mut self, actual: &Win16WindowSourceRetiredProof)
        -> Result<(), RuntimeError>
    {
        assert_eq!(actual, proof().as_ref());
        self.consumed += 1;
        Ok(())
    }
    fn epoch_seconds(&self) -> i64 { panic!("unexpected host call") }
    fn read_bios_key(&mut self) -> Result<KeyStroke, RuntimeError> { panic!("unexpected host call") }
    fn render_text(&mut self, _screen: &ConsoleSnapshot) -> Result<(), RuntimeError> { panic!("unexpected host call") }
}
impl crate::RuntimeDdeHost for DestroyReceiptHost {
    fn win16_dde_abort(&mut self) -> crate::Win16DdeAbortReceipt { panic!("unexpected host call") }
}
impl crate::RuntimeMciHost for DestroyReceiptHost {}
impl crate::RuntimeMidiHost for DestroyReceiptHost {}
impl crate::RuntimeNetbiosHost for DestroyReceiptHost {}

fn fixture() -> Runtime {
    let mut runtime = Runtime::load(&tiny_ne_executable(), &[], br"C:\DESTROY.NE").unwrap();
    assert!(runtime.memory.len() >= 1024 * 1024);
    insert_window(&mut runtime, ROOT_GUEST, ROOT, true);
    runtime
}

fn insert_window(runtime: &mut Runtime, guest: u16, native: Win16HostWindow, owned: bool) {
    let state = runtime.win16.as_mut().unwrap();
    state.window_handles.insert(guest, native);
    if owned {
        state.owned_window_handles.insert(guest);
    }
}

fn prepare(runtime: &mut Runtime, window: u16) -> (u16, u16, u16) {
    let descriptor = lookup_export(b"USER", ExportLookupTarget::Ordinal(53)).unwrap();
    assert_eq!(descriptor.id,
        lookup_export(b"USER", ExportLookupTarget::Name(b"DestroyWindow")).unwrap().id);
    let win16_abi::Win16ExportStackCleanup::Fixed(cleanup) = descriptor.stack_cleanup
        else { panic!("DestroyWindow must use fixed Pascal cleanup"); };
    assert_eq!(cleanup.callee_pop_bytes, 2);
    assert_eq!(cleanup.caller_pop_bytes, 0);
    assert_eq!(descriptor.return_kind, win16_abi::Win16ReturnKind::Word);
    let return_cs = runtime.cpu.regs.cs;
    let return_ip = 0x12_u16;
    let stack = runtime.cpu.regs.sp();
    let state = runtime.win16.as_mut().unwrap();
    let mut bytes = Vec::from(return_ip.to_le_bytes());
    bytes.extend_from_slice(&return_cs.to_le_bytes());
    bytes.extend_from_slice(&window.to_le_bytes());
    let pointer = state.selectors.pointer_from_raw(Selector(runtime.cpu.regs.ss), stack).unwrap();
    state.selectors.write(&mut runtime.memory, pointer, &bytes).unwrap();
    let slot = state.bindings.len();
    state.bindings.push(ImportBinding::Supported(descriptor));
    runtime.cpu.regs.cs = state.gate_selector.0;
    runtime.cpu.regs.set_ip((slot * 2) as u16);
    runtime.cpu.regs.set_ax(AX);
    runtime.cpu.regs.set_dx(DX);
    (return_cs, return_ip, stack + bytes.len() as u16)
}

fn dispatch(runtime: &mut Runtime, host: &mut DestroyReceiptHost) -> Result<Option<u8>, RuntimeError> {
    runtime.win16.as_mut().unwrap().dispatch(
        &mut runtime.cpu, &mut runtime.memory, &mut runtime.dos, host, 0,
    )
}

fn retry(runtime: &mut Runtime, host: &mut DestroyReceiptHost) -> Result<(), RuntimeError> {
    runtime.win16.as_mut().unwrap().drive_pending_window_completion(
        &mut runtime.cpu, &mut runtime.memory, &mut runtime.dos, host,
    )
}

fn assert_return(runtime: &Runtime, return_to: (u16, u16, u16), value: u16) {
    assert_eq!(runtime.cpu.regs.ax(), value);
    assert_eq!(runtime.cpu.regs.dx(), DX, "WORD result preserves DX");
    assert_eq!((runtime.cpu.regs.cs, runtime.cpu.regs.ip(), runtime.cpu.regs.sp()), return_to);
    let state = runtime.win16.as_ref().unwrap();
    assert!(state.window_operations.is_empty());
    assert!(state.window_callbacks.is_empty());
}

fn assert_retired(runtime: &Runtime, guests: &[u16]) {
    let state = runtime.win16.as_ref().unwrap();
    for guest in guests {
        assert!(!state.window_handles.contains_key(guest));
        assert!(!state.owned_window_handles.contains(guest));
        assert!(!state.window_creations.contains_key(guest));
        assert!(!state.window_system_classes.contains_key(guest));
        assert!(!state.window_data.contains_key(guest));
    }
}

fn assert_cached_batch(runtime: &Runtime, windows: &[Win16HostWindow], menus: &[Win16HostMenu]) -> u64 {
    let state = runtime.win16.as_ref().unwrap();
    assert_eq!(state.window_operations.len(), 1);
    let frame = state.window_operations.last().unwrap();
    let completion = frame.completion.as_ref().expect("retain the native result until cleanup succeeds");
    let Win16WindowResult::WindowCall(Win16WindowCallResult::Destroyed { retirements, .. })
        = &completion.result else { panic!("retain the exact DestroyWindow completion"); };
    assert_eq!(retirements.receipts.iter().map(|receipt| receipt.window).collect::<Vec<_>>(), windows);
    assert_eq!(retirements.invalidated_menus, menus);
    frame.id
}

#[test]
fn destroy_receipts_retire_callback_free_owned_popup_without_parent_edge() {
    let mut runtime = fixture();
    insert_window(&mut runtime, POPUP_GUEST, POPUP, true);
    insert_window(&mut runtime, CHILD_GUEST, CHILD, false);
    let state = runtime.win16.as_mut().unwrap();
    assert!(!state.window_parents.contains_key(&POPUP_GUEST));
    assert!(state.window_procedures.is_empty());
    state.window_creations.insert(POPUP_GUEST, crate::Win16CreationId(7));
    state.window_system_classes.insert(POPUP_GUEST, crate::Win16HostSystemClass::Static);
    state.initialize_window_data(POPUP_GUEST, None, 0x4321, false, Some(8)).unwrap();
    assert!(state.window_data.contains_key(&POPUP_GUEST));
    let menu = state.guest_menus.intern(MENU).unwrap();
    let other_menu_token = Win16HostMenu(MENU.0 + 1);
    let other_menu = state.guest_menus.intern(other_menu_token).unwrap();
    let return_to = prepare(&mut runtime, ROOT_GUEST);
    let mut host = DestroyReceiptHost::new(true, &[ROOT, POPUP], &[MENU]);

    dispatch(&mut runtime, &mut host).unwrap();

    assert_eq!(host.calls, [Win16WindowTarget::Mapped(ROOT)]);
    assert_eq!(host.consumed, 1);
    assert_retired(&runtime, &[ROOT_GUEST, POPUP_GUEST]);
    let state = runtime.win16.as_ref().unwrap();
    assert_eq!(state.window_handles[&CHILD_GUEST], CHILD);
    assert_eq!(state.guest_menus.resolve(menu), None);
    assert_eq!(state.guest_menus.resolve(other_menu), Some(other_menu_token));
    assert_return(&runtime, return_to, 1);
    // The formerly callback-free popup cannot expose its saved HINSTANCE
    // after the host has proved that exact incarnation dead.
    let mut registers = runtime.cpu.regs.clone();
    runtime.win16.as_mut().unwrap().begin_window_data(
        &mut registers, &mut runtime.memory, &mut host,
        win16_abi::Win16WindowDataRequest::GetWindowWord {
            window: POPUP_GUEST,
            index: win16_abi::exports::window_data::GWW_HINSTANCE,
        },
        (return_to.0, return_to.1, u32::from(return_to.2)),
    ).unwrap();
    assert_eq!(registers.ax(), 0);
    assert_eq!(host.calls, [Win16WindowTarget::Mapped(ROOT)]);
}

#[test]
fn destroy_receipts_retire_borrowed_target_and_every_exact_alias() {
    let mut runtime = fixture();
    insert_window(&mut runtime, ALIAS_GUEST, ROOT, false);
    insert_window(&mut runtime, POPUP_GUEST, POPUP, false);
    let return_to = prepare(&mut runtime, ALIAS_GUEST);
    let mut host = DestroyReceiptHost::new(true, &[ROOT, POPUP], &[]);

    dispatch(&mut runtime, &mut host).unwrap();

    assert_eq!(host.calls, [Win16WindowTarget::Mapped(ROOT)]);
    assert_eq!(host.consumed, 1);
    assert_retired(&runtime, &[ROOT_GUEST, ALIAS_GUEST, POPUP_GUEST]);
    assert_return(&runtime, return_to, 1);
}

#[test]
fn destroy_receipts_apply_windows_and_menus_even_when_native_bool_is_false() {
    let mut runtime = fixture();
    let menu = runtime.win16.as_mut().unwrap().guest_menus.intern(MENU).unwrap();
    let return_to = prepare(&mut runtime, ROOT_GUEST);
    let mut host = DestroyReceiptHost::new(false, &[ROOT], &[MENU]);

    dispatch(&mut runtime, &mut host).unwrap();

    assert_retired(&runtime, &[ROOT_GUEST]);
    assert_eq!(runtime.win16.as_ref().unwrap().guest_menus.resolve(menu), None);
    assert_eq!(host.consumed, 1);
    assert_return(&runtime, return_to, 0);
}

#[test]
fn destroy_receipts_reject_duplicate_token_before_any_window_or_menu_mutation() {
    let mut runtime = fixture();
    insert_window(&mut runtime, POPUP_GUEST, POPUP, true);
    insert_window(&mut runtime, ALIAS_GUEST, ROOT, false);
    let state = runtime.win16.as_mut().unwrap();
    state.link_window_parent(POPUP_GUEST, ROOT_GUEST).unwrap();
    state.window_creations.insert(POPUP_GUEST, crate::Win16CreationId(7));
    let menu = state.guest_menus.intern(MENU).unwrap();
    let handles = state.window_handles.clone();
    let owned = state.owned_window_handles.clone();
    let parents = state.window_parents.clone();
    let creations = state.window_creations.clone();
    prepare(&mut runtime, ROOT_GUEST);
    let registers = runtime.cpu.regs.clone();
    let mut host = DestroyReceiptHost::new(true, &[ROOT, POPUP, ROOT], &[MENU]);

    assert_eq!(dispatch(&mut runtime, &mut host).unwrap_err().kind(), Kind::InternalInvariant);

    let frame_id = assert_cached_batch(&runtime, &[ROOT, POPUP, ROOT], &[MENU]);
    let state = runtime.win16.as_ref().unwrap();
    assert_eq!(state.window_handles, handles);
    assert_eq!(state.owned_window_handles, owned);
    assert_eq!(state.window_parents, parents);
    assert_eq!(state.window_creations, creations);
    assert_eq!(state.guest_menus.resolve(menu), Some(MENU));
    assert_eq!(runtime.cpu.regs, registers);
    assert_eq!(host.calls, [Win16WindowTarget::Mapped(ROOT)]);
    assert_eq!(host.consumed, 0);
    // Retrying a malformed cached batch must neither rerun USER nor partially
    // accept a prefix that would make its second occurrence disappear.
    assert_eq!(retry(&mut runtime, &mut host).unwrap_err().kind(), Kind::InternalInvariant);
    assert_eq!(assert_cached_batch(&runtime, &[ROOT, POPUP, ROOT], &[MENU]), frame_id);
    assert_eq!(runtime.win16.as_ref().unwrap().window_handles, handles);
    assert_eq!(runtime.win16.as_ref().unwrap().guest_menus.resolve(menu), Some(MENU));
    assert_eq!(host.calls.len(), 1);
}

#[test]
fn destroy_receipts_preserve_unreceipted_children_and_grandchildren() {
    let mut runtime = fixture();
    insert_window(&mut runtime, CHILD_GUEST, CHILD, true);
    insert_window(&mut runtime, POPUP_GUEST, POPUP, true);
    let state = runtime.win16.as_mut().unwrap();
    state.link_window_parent(CHILD_GUEST, ROOT_GUEST).unwrap();
    state.link_window_parent(POPUP_GUEST, CHILD_GUEST).unwrap();
    state.window_creations.insert(CHILD_GUEST, crate::Win16CreationId(9));
    state.window_system_classes.insert(CHILD_GUEST, crate::Win16HostSystemClass::Edit);
    state.initialize_window_data(CHILD_GUEST, None, 0x5432, false, Some(8)).unwrap();
    let return_to = prepare(&mut runtime, ROOT_GUEST);
    let mut host = DestroyReceiptHost::new(true, &[ROOT], &[]);

    dispatch(&mut runtime, &mut host).unwrap();

    assert_retired(&runtime, &[ROOT_GUEST]);
    let state = runtime.win16.as_ref().unwrap();
    assert_eq!(state.window_handles[&CHILD_GUEST], CHILD);
    assert_eq!(state.window_handles[&POPUP_GUEST], POPUP);
    assert!(state.owned_window_handles.contains(&CHILD_GUEST));
    assert!(state.owned_window_handles.contains(&POPUP_GUEST));
    assert!(!state.window_parents.contains_key(&CHILD_GUEST),
        "surviving child must not retain an edge to a reusable retired parent slot");
    assert_eq!(state.window_parents[&POPUP_GUEST], CHILD_GUEST);
    assert_eq!(state.window_creations[&CHILD_GUEST], crate::Win16CreationId(9));
    assert_eq!(state.window_system_classes[&CHILD_GUEST], crate::Win16HostSystemClass::Edit);
    assert!(state.window_data.contains_key(&CHILD_GUEST));
    assert_return(&runtime, return_to, 1);
}

#[test]
fn destroy_receipts_do_not_infer_owned_root_retirement_from_successful_bool() {
    let mut runtime = fixture();
    insert_window(&mut runtime, CHILD_GUEST, CHILD, true);
    let state = runtime.win16.as_mut().unwrap();
    state.link_window_parent(CHILD_GUEST, ROOT_GUEST).unwrap();
    let handles = state.window_handles.clone();
    let owned = state.owned_window_handles.clone();
    let parents = state.window_parents.clone();
    let return_to = prepare(&mut runtime, ROOT_GUEST);
    let mut host = DestroyReceiptHost::new(true, &[], &[]);

    dispatch(&mut runtime, &mut host).unwrap();

    let state = runtime.win16.as_ref().unwrap();
    assert_eq!(state.window_handles, handles);
    assert_eq!(state.owned_window_handles, owned);
    assert_eq!(state.window_parents, parents);
    assert_return(&runtime, return_to, 1);
}

#[test]
fn destroy_receipts_preserve_replaced_guest_slot_after_source_readback_retry() {
    let mut runtime = fixture();
    insert_window(&mut runtime, ALIAS_GUEST, ROOT, false);
    insert_window(&mut runtime, POPUP_GUEST, POPUP, true);
    let return_to = prepare(&mut runtime, ROOT_GUEST);
    let mut host = DestroyReceiptHost::new(true, &[ROOT, POPUP], &[]);
    host.fail_readback_once = true;
    assert_eq!(dispatch(&mut runtime, &mut host).unwrap_err().kind(), Kind::HostFailure);
    let frame_id = assert_cached_batch(&runtime, &[ROOT, POPUP], &[]);
    assert_eq!(host.calls, [Win16WindowTarget::Mapped(ROOT)]);
    assert_eq!(host.consumed, 0);
    assert_eq!(runtime.cpu.regs.ax(), AX);
    // Reentrant guest work may reuse the WORD slot while the exact old native
    // result is retained. Its borrowed alias still names the old incarnation.
    insert_window(&mut runtime, ROOT_GUEST, REPLACEMENT, true);
    runtime.win16.as_mut().unwrap().window_creations.insert(ROOT_GUEST, crate::Win16CreationId(8));
    assert_eq!(assert_cached_batch(&runtime, &[ROOT, POPUP], &[]), frame_id);

    retry(&mut runtime, &mut host).unwrap();

    assert_eq!(host.calls, [Win16WindowTarget::Mapped(ROOT)]);
    assert_eq!(host.consumed, 1);
    assert_retired(&runtime, &[ALIAS_GUEST, POPUP_GUEST]);
    let state = runtime.win16.as_ref().unwrap();
    assert_eq!(state.window_handles[&ROOT_GUEST], REPLACEMENT);
    assert!(state.owned_window_handles.contains(&ROOT_GUEST));
    assert_eq!(state.window_creations[&ROOT_GUEST], crate::Win16CreationId(8));
    assert_return(&runtime, return_to, 1);
}

#[test]
fn destroy_receipts_retry_partial_cleanup_from_cached_batch_without_second_native_call() {
    let mut runtime = fixture();
    insert_window(&mut runtime, POPUP_GUEST, POPUP, true);
    insert_window(&mut runtime, CHILD_GUEST, CHILD, true);
    let mut host = DestroyReceiptHost::new(true, &[ROOT, POPUP], &[MENU]);
    let state = runtime.win16.as_mut().unwrap();
    state.link_window_parent(CHILD_GUEST, POPUP_GUEST).unwrap();
    let menu = state.guest_menus.intern(MENU).unwrap();
    let queued = crate::Win16HostQueuedDropFiles {
        lease: crate::Win16HostDropFilesLease(71),
        native_removed: false,
        files: crate::Win16HostDropFiles {
            paths: vec![br"C:\DROP.TXT".to_vec()],
            point: crate::Win16HostPoint { x: 0, y: 0 },
            in_client_area: true,
        },
    };
    let drop = state.project_queued_drop_files_hglobal(
        &queued, POPUP, &mut runtime.memory, &mut host,
    ).unwrap().unwrap();
    assert_eq!(state.global_free(drop).unwrap(), drop, "native queue pin retains DragFinish");
    // Inject a repairable cleanup invariant after a real queue-owned HGLOBAL
    // has been allocated. GlobalFree must retain this exact owner when its
    // primary-selector mapping is missing, then succeed after it is restored.
    let selector = state.global_selectors.remove(&drop).unwrap();
    let allocation = state.global_handles[&drop];
    let return_to = prepare(&mut runtime, ROOT_GUEST);

    assert_eq!(dispatch(&mut runtime, &mut host).unwrap_err().kind(), Kind::InternalInvariant);

    let frame_id = assert_cached_batch(&runtime, &[ROOT, POPUP], &[MENU]);
    assert_retired(&runtime, &[ROOT_GUEST]);
    let state = runtime.win16.as_mut().unwrap();
    assert_eq!(state.window_handles[&POPUP_GUEST], POPUP);
    assert_eq!(state.window_parents[&CHILD_GUEST], POPUP_GUEST,
        "cleanup failure must preserve the retained parent's incoming edges");
    assert_eq!(state.global_handles[&drop], allocation);
    assert_eq!(state.guest_menus.resolve(menu), Some(MENU));
    assert_eq!(runtime.cpu.regs.ax(), AX);
    assert_eq!(host.consumed, 0);
    state.global_selectors.insert(drop, selector);
    // An already retired prefix can be replaced before the batch retry.
    // Receipt replay must find its old token, never clean up its reused slot.
    insert_window(&mut runtime, ROOT_GUEST, REPLACEMENT, true);
    assert_eq!(assert_cached_batch(&runtime, &[ROOT, POPUP], &[MENU]), frame_id);

    retry(&mut runtime, &mut host).unwrap();

    assert_eq!(host.calls, [Win16WindowTarget::Mapped(ROOT)]);
    assert_eq!(host.consumed, 1);
    assert_retired(&runtime, &[POPUP_GUEST]);
    let state = runtime.win16.as_ref().unwrap();
    assert_eq!(state.window_handles[&ROOT_GUEST], REPLACEMENT);
    assert!(state.owned_window_handles.contains(&ROOT_GUEST));
    assert_eq!(state.window_handles[&CHILD_GUEST], CHILD);
    assert!(state.owned_window_handles.contains(&CHILD_GUEST));
    assert!(!state.window_parents.contains_key(&CHILD_GUEST));
    assert!(!state.global_handles.contains_key(&drop));
    assert!(state.queued_drop_files.is_empty());
    assert_eq!(state.guest_menus.resolve(menu), None);
    assert_return(&runtime, return_to, 1);
}

#[test]
fn destroy_receipts_complete_null_and_invalid_target_calls() {
    for (guest, target) in [(0, Win16WindowTarget::Null), (0xdead, Win16WindowTarget::Invalid)] {
        let mut runtime = fixture();
        let return_to = prepare(&mut runtime, guest);
        let mut host = DestroyReceiptHost::new(false, &[], &[]);

        dispatch(&mut runtime, &mut host).unwrap();

        assert_eq!(host.calls, [target]);
        assert_eq!(host.consumed, 1);
        assert_eq!(runtime.win16.as_ref().unwrap().window_handles[&ROOT_GUEST], ROOT);
        assert_return(&runtime, return_to, 0);
    }
}

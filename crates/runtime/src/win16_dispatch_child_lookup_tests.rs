//! Service-gate regression coverage for USER.48, USER.191 and USER.399.
//! Native USER owns hierarchy/hit-test policy; these tests verify ABI, routing,
//! exact coordinate/flag forwarding, opaque identity and result projection.

use super::super::{ImportBinding, test_support::tiny_ne_executable};
use crate::{
    DiagnosticKind as Kind, Runtime, RuntimeError, RuntimeHost, Win16HostPoint,
    Win16HostWindow, Win16HostWindowOperationId, Win16NativeWindowOperationKind,
    Win16NativeWindowOperationProof, Win16NativeWindowOperationState, Win16WindowCall,
    Win16WindowCallResult, Win16WindowOperation, Win16WindowResult,
    Win16WindowSourceRetiredProof, Win16WindowStep, Win16WindowTarget,
};
use devices::{keyboard::KeyStroke, video::ConsoleSnapshot};
use dos_kernel::{
    DosDirectoryEntry, DosFileAccess, DosFileSharing, DosHost, DosHostError,
    DosHostFile, DosHostSearch, DosSeekOrigin,
};
use guest_core::Selector;
use std::sync::Arc;
use win16_abi::{ExportLookupTarget, Win16ExportStackCleanup, Win16ReturnKind, lookup_export};

const AX: u16 = 0xa55a;
const DX: u16 = 0x5aa5;
const PARENT: Win16HostWindow = Win16HostWindow(0x1234_5678_9abc);
const CHILD: Win16HostWindow = Win16HostWindow(0xabcd_1234_5678);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Query {
    Hit { parent: Win16WindowTarget, point: Win16HostPoint, flags: Option<u16> },
    IsChild { parent: Win16WindowTarget, child: Win16WindowTarget },
}

#[derive(Default)]
struct ChildLookupHost {
    calls: Vec<Query>,
    result: Option<Win16WindowCallResult>,
    consumed: usize,
    fail_readback_once: bool,
}

fn proof() -> Arc<Win16WindowSourceRetiredProof> {
    Arc::new(Win16WindowSourceRetiredProof {
        operation: Win16NativeWindowOperationProof {
            operation_id: Win16HostWindowOperationId(41),
            kind: Win16NativeWindowOperationKind::WindowCall,
        },
        worker_generation: 7,
        state: Win16NativeWindowOperationState::Returned,
    })
}

impl DosHost for ChildLookupHost {
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

impl RuntimeHost for ChildLookupHost {
    fn win16_window_begin(&mut self, operation: Win16WindowOperation) -> Result<Win16WindowStep, RuntimeError> {
        let query = match operation {
            Win16WindowOperation::WindowCall(Win16WindowCall::ChildWindowFromPoint { parent, point }) =>
                Query::Hit { parent, point, flags: None },
            Win16WindowOperation::WindowCall(Win16WindowCall::ChildWindowFromPointEx { parent, point, flags }) =>
                Query::Hit { parent, point, flags: Some(flags) },
            Win16WindowOperation::WindowCall(Win16WindowCall::IsChild { parent, child }) =>
                Query::IsChild { parent, child },
            _ => panic!("unexpected host operation"),
        };
        self.calls.push(query);
        let proof = proof();
        Ok(Win16WindowStep::Started {
            operation_id: proof.operation.operation_id,
            worker_generation: proof.worker_generation,
            kind: proof.operation.kind,
            step: Box::new(Win16WindowStep::SourceRetired {
                proof,
                result: Box::new(Win16WindowStep::Complete(Win16WindowResult::WindowCall(
                    self.result.take().expect("test must supply a native result"),
                ))),
            }),
        })
    }
    fn win16_window_source_retirement(
        &mut self, operation: Win16NativeWindowOperationProof, worker_generation: u64,
    ) -> Result<Option<Arc<Win16WindowSourceRetiredProof>>, RuntimeError> {
        let proof = proof();
        assert_eq!(operation, proof.operation);
        assert_eq!(worker_generation, proof.worker_generation);
        if std::mem::take(&mut self.fail_readback_once) {
            return Err(RuntimeError::new(Kind::HostFailure, "test defers the retained lookup result"));
        }
        Ok(Some(proof))
    }
    fn win16_window_source_retirement_consumed(&mut self, actual: &Win16WindowSourceRetiredProof) -> Result<(), RuntimeError> {
        assert_eq!(actual, proof().as_ref());
        self.consumed += 1;
        Ok(())
    }
    fn epoch_seconds(&self) -> i64 { panic!("unexpected host call") }
    fn read_bios_key(&mut self) -> Result<KeyStroke, RuntimeError> { panic!("unexpected host call") }
    fn render_text(&mut self, _screen: &ConsoleSnapshot) -> Result<(), RuntimeError> { panic!("unexpected host call") }
}
impl crate::RuntimeDdeHost for ChildLookupHost {
    fn win16_dde_abort(&mut self) -> crate::Win16DdeAbortReceipt { panic!("unexpected host call") }
}
impl crate::RuntimeMciHost for ChildLookupHost {}
impl crate::RuntimeMidiHost for ChildLookupHost {}
impl crate::RuntimeNetbiosHost for ChildLookupHost {}

fn fixture() -> Runtime {
    let mut runtime = Runtime::load(&tiny_ne_executable(), &[], br"C:\CHILD.NE").unwrap();
    let state = runtime.win16.as_mut().unwrap();
    state.window_handles.insert(0x1234, PARENT);
    state.window_handles.insert(0x2345, CHILD);
    state.owned_window_handles.insert(0x1234);
    runtime
}

fn prepare(runtime: &mut Runtime, ordinal: u16, parent: u16, value: u32, flags: u16) -> (u16, u16, u16) {
    let descriptor = lookup_export(b"USER", ExportLookupTarget::Ordinal(ordinal)).unwrap();
    assert_eq!(descriptor.return_kind, Win16ReturnKind::Word);
    let Win16ExportStackCleanup::Fixed(cleanup) = descriptor.stack_cleanup else {
        panic!("child queries require fixed Pascal frames");
    };
    assert_eq!(cleanup.callee_pop_bytes, match ordinal { 48 => 4, 191 => 6, 399 => 8, _ => unreachable!() });
    assert_eq!(cleanup.caller_pop_bytes, 0);
    let return_cs = runtime.cpu.regs.cs;
    let return_ip = 0x12_u16;
    let stack = runtime.cpu.regs.sp();
    let state = runtime.win16.as_mut().unwrap();
    let mut bytes = Vec::from(return_ip.to_le_bytes());
    bytes.extend_from_slice(&return_cs.to_le_bytes());
    if ordinal == 399 { bytes.extend_from_slice(&flags.to_le_bytes()); }
    if ordinal == 48 { bytes.extend_from_slice(&(value as u16).to_le_bytes()); }
    else { bytes.extend_from_slice(&value.to_le_bytes()); }
    bytes.extend_from_slice(&parent.to_le_bytes());
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

fn dispatch(runtime: &mut Runtime, host: &mut ChildLookupHost) -> Result<Option<u8>, RuntimeError> {
    runtime.win16.as_mut().unwrap().dispatch(
        &mut runtime.cpu, &mut runtime.memory, &mut runtime.dos, host, 0,
    )
}

fn assert_return(runtime: &Runtime, return_to: (u16, u16, u16), value: u16) {
    assert_eq!(runtime.cpu.regs.ax(), value);
    assert_eq!(runtime.cpu.regs.dx(), DX, "WORD return preserves DX");
    assert_eq!((runtime.cpu.regs.cs, runtime.cpu.regs.ip(), runtime.cpu.regs.sp()), return_to);
    assert!(runtime.win16.as_ref().unwrap().window_operations.is_empty());
}

fn packed(x: i16, y: i16) -> u32 {
    u32::from(x as u16) | (u32::from(y as u16) << 16)
}

#[test]
fn child_lookup_preserves_signed_client_coordinates_and_all_flag_bits() {
    for ordinal in [191, 399] {
        for (x, y) in [(i16::MIN, i16::MAX), (i16::MAX, i16::MIN), (-19, 23), (-1, -1), (0, 0)] {
            for flags in [0, 1, 2, 4, 7, 0x8000, 0xffff] {
                let mut runtime = fixture();
                let return_to = prepare(&mut runtime, ordinal, 0x1234, packed(x, y), flags);
                let mut host = ChildLookupHost {
                    result: Some(Win16WindowCallResult::Window(Some(CHILD))), ..Default::default()
                };
                assert_eq!(dispatch(&mut runtime, &mut host).unwrap(), None);
                assert_eq!(host.calls, [Query::Hit {
                    parent: Win16WindowTarget::Mapped(PARENT),
                    point: Win16HostPoint { x: i32::from(x), y: i32::from(y) },
                    flags: (ordinal == 399).then_some(flags),
                }]);
                assert_eq!(host.consumed, 1);
                assert_return(&runtime, return_to, 0x2345);
            }
        }
    }
}

#[test]
fn child_lookup_projects_parent_child_and_no_hit_without_changing_ownership_or_hierarchy() {
    for ordinal in [191, 399] {
        for (native, expected) in [(Some(PARENT), 0x1234), (Some(CHILD), 0x2345), (None, 0)] {
            let mut runtime = fixture();
            let state = runtime.win16.as_mut().unwrap();
            // Runtime metadata is not an authority for native hit testing.
            state.window_parents.insert(0x2345, 0x7777);
            let parents = state.window_parents.clone();
            let owners = state.owned_window_handles.clone();
            let handles = state.window_handles.clone();
            let return_to = prepare(&mut runtime, ordinal, 0x1234, packed(25, 30), 7);
            let mut host = ChildLookupHost {
                result: Some(Win16WindowCallResult::Window(native)), ..Default::default()
            };
            dispatch(&mut runtime, &mut host).unwrap();
            assert_return(&runtime, return_to, expected);
            let state = runtime.win16.as_ref().unwrap();
            assert_eq!(state.window_handles, handles);
            assert_eq!(state.window_parents, parents);
            assert_eq!(state.owned_window_handles, owners);
        }
    }
}

#[test]
fn child_lookup_interns_new_opaque_results_and_reuses_the_guest_handle() {
    let mut runtime = fixture();
    let native = Win16HostWindow(0xfedc_ba98_7654);
    let mut first = None;
    for ordinal in [191, 399, 191] {
        let return_to = prepare(&mut runtime, ordinal, 0x1234, 0, 0);
        let mut host = ChildLookupHost {
            result: Some(Win16WindowCallResult::Window(Some(native))), ..Default::default()
        };
        dispatch(&mut runtime, &mut host).unwrap();
        let guest = runtime.cpu.regs.ax();
        assert!(!matches!(guest, 0 | 1 | 0xfffe | 0xffff));
        assert_return(&runtime, return_to, guest);
        if let Some(first) = first { assert_eq!(guest, first); } else { first = Some(guest); }
        let state = runtime.win16.as_ref().unwrap();
        assert_eq!(state.window_handles.get(&guest), Some(&native));
        assert!(!state.owned_window_handles.contains(&guest));
        assert!(!state.window_parents.contains_key(&guest));
    }
    assert_eq!(runtime.win16.as_ref().unwrap().window_handles.len(), 3);
}

#[test]
fn child_lookup_keeps_null_unknown_retired_and_mapped_parent_inputs_distinct() {
    for ordinal in [191, 399] {
        for (parent, expected, retired) in [
            (0, Win16WindowTarget::Null, false),
            (0xffff, Win16WindowTarget::Invalid, false),
            (0x4321, Win16WindowTarget::Invalid, false),
            (0x1234, Win16WindowTarget::Invalid, true),
            (0x1234, Win16WindowTarget::Mapped(PARENT), false),
        ] {
            let mut runtime = fixture();
            if retired { runtime.win16.as_mut().unwrap().window_handles.remove(&0x1234); }
            let return_to = prepare(&mut runtime, ordinal, parent, 0xffff_ffff, 7);
            // Native USER/identity validation also rejects stale mapped tokens.
            let mut host = ChildLookupHost {
                result: Some(Win16WindowCallResult::Window(None)), ..Default::default()
            };
            dispatch(&mut runtime, &mut host).unwrap();
            assert_eq!(host.calls, [Query::Hit { parent: expected,
                point: Win16HostPoint { x: -1, y: -1 }, flags: (ordinal == 399).then_some(7) }]);
            assert_return(&runtime, return_to, 0);
        }
    }
}

#[test]
fn child_lookup_is_child_marshals_both_handles_and_uses_native_descendant_results() {
    for (parent, child, expected_parent, expected_child) in [
        (0x1234, 0x2345_u16, Win16WindowTarget::Mapped(PARENT), Win16WindowTarget::Mapped(CHILD)),
        (0x1234, 0x1234, Win16WindowTarget::Mapped(PARENT), Win16WindowTarget::Mapped(PARENT)),
        (0, 0x2345, Win16WindowTarget::Null, Win16WindowTarget::Mapped(CHILD)),
        (0x1234, 0, Win16WindowTarget::Mapped(PARENT), Win16WindowTarget::Null),
        (0xffff, 0x2345, Win16WindowTarget::Invalid, Win16WindowTarget::Mapped(CHILD)),
        (0x1234, 0xffff, Win16WindowTarget::Mapped(PARENT), Win16WindowTarget::Invalid),
    ] {
        let mut runtime = fixture();
        let state = runtime.win16.as_mut().unwrap();
        state.window_parents.insert(0x2345, 0x1234);
        let return_to = prepare(&mut runtime, 48, parent, u32::from(child), 0);
        let mut host = ChildLookupHost {
            result: Some(Win16WindowCallResult::Boolean(false)), ..Default::default()
        };
        dispatch(&mut runtime, &mut host).unwrap();
        assert_eq!(host.calls, [Query::IsChild { parent: expected_parent, child: expected_child }]);
        assert_return(&runtime, return_to, 0);
    }
    let mut runtime = fixture();
    // No guest parent metadata exists for this native descendant relationship.
    assert!(runtime.win16.as_ref().unwrap().window_parents.is_empty());
    let return_to = prepare(&mut runtime, 48, 0x1234, 0x2345, 0);
    let mut host = ChildLookupHost {
        result: Some(Win16WindowCallResult::Boolean(true)), ..Default::default()
    };
    dispatch(&mut runtime, &mut host).unwrap();
    assert_return(&runtime, return_to, 1);
}

#[test]
fn child_lookup_retries_retained_results_without_repeating_native_queries() {
    for (ordinal, result, value) in [
        (48, Win16WindowCallResult::Boolean(true), 0x2345),
        (191, Win16WindowCallResult::Window(Some(CHILD)), 0x8000_7fff),
        (399, Win16WindowCallResult::Window(Some(CHILD)), 0x8000_7fff),
    ] {
        let mut runtime = fixture();
        let return_to = prepare(&mut runtime, ordinal, 0x1234, value, 7);
        let mut host = ChildLookupHost { result: Some(result), fail_readback_once: true, ..Default::default() };
        assert_eq!(dispatch(&mut runtime, &mut host).unwrap_err().kind(), Kind::HostFailure);
        assert_eq!(host.calls.len(), 1);
        assert_eq!(host.consumed, 0);
        assert_eq!(runtime.cpu.regs.ax(), AX);
        runtime.win16.as_mut().unwrap().drive_pending_window_completion(
            &mut runtime.cpu, &mut runtime.memory, &mut runtime.dos, &mut host,
        ).unwrap();
        assert_eq!(host.calls.len(), 1);
        assert_eq!(host.consumed, 1);
        assert_return(&runtime, return_to, if ordinal == 48 { 1 } else { 0x2345 });
    }
}

#[test]
fn child_lookup_rejects_unexpected_output_shapes_before_returning() {
    let mut runtime = fixture();
    prepare(&mut runtime, 191, 0x1234, 0, 0);
    let mut host = ChildLookupHost {
        result: Some(Win16WindowCallResult::Points(None)), ..Default::default()
    };
    assert_eq!(dispatch(&mut runtime, &mut host).unwrap_err().kind(), Kind::InternalInvariant);
    assert_eq!(runtime.cpu.regs.ax(), AX);
    assert_eq!(host.consumed, 0);
}

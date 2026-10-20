//! SetAbortProc stores a guest AbortProc, and QueryAbort plus print calls enter it.
use super::super::{ImportBinding, test_support::tiny_ne_executable};
use super::*;
use crate::{
    Runtime, RuntimeError, RuntimeHost, Win16GdiDeviceOperation as Operation,
    Win16GdiDeviceResult as HostResult, Win16HostDc, Win16PrintOperation,
};
use devices::{keyboard::KeyStroke, video::ConsoleSnapshot};
use dos_kernel::{
    DosDirectoryEntry, DosFileAccess, DosFileSharing, DosHost, DosHostError, DosHostFile,
    DosHostSearch, DosSeekOrigin,
};
use guest_core::{GuestMemory, PhysAddr, Selector, io::NoPorts};
use win16_abi::{Access, AccessRights, ExportLookupTarget, SegmentedPointer, lookup_export};

const NATIVE: Win16HostDc = Win16HostDc(0x1234);
const SP_ERROR: u16 = 0xffff;
const SP_APPABORT: u16 = 0xfffe;

#[derive(Default)]
struct Host {
    calls: Vec<Operation>,
}

impl DosHost for Host {
    fn read_stdin(&mut self, _: &mut [u8]) -> Result<usize, DosHostError> {
        panic!("unexpected host call")
    }
    fn try_read_stdin(&mut self) -> Result<Option<u8>, DosHostError> {
        panic!("unexpected host call")
    }
    fn write_stdout(&mut self, _: &[u8]) -> Result<usize, DosHostError> {
        panic!("unexpected host call")
    }
    fn write_stderr(&mut self, _: &[u8]) -> Result<usize, DosHostError> {
        panic!("unexpected host call")
    }
    fn flush_stdin(&mut self) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn file_create(&mut self, _: &[u8], _: u8) -> Result<DosHostFile, DosHostError> {
        panic!("unexpected host call")
    }
    fn file_open(&mut self, _: &[u8], _: DosFileAccess) -> Result<DosHostFile, DosHostError> {
        panic!("unexpected host call")
    }
    fn file_open_with_sharing(
        &mut self,
        _: &[u8],
        _: DosFileAccess,
        _: DosFileSharing,
    ) -> Result<DosHostFile, DosHostError> {
        panic!("unexpected host call")
    }
    fn file_duplicate(&mut self, _: DosHostFile) -> Result<DosHostFile, DosHostError> {
        panic!("unexpected host call")
    }
    fn file_close(&mut self, _: DosHostFile) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn file_read(&mut self, _: DosHostFile, _: &mut [u8]) -> Result<usize, DosHostError> {
        panic!("unexpected host call")
    }
    fn file_write(&mut self, _: DosHostFile, _: &[u8]) -> Result<usize, DosHostError> {
        panic!("unexpected host call")
    }
    fn file_seek(&mut self, _: DosHostFile, _: i32, _: DosSeekOrigin) -> Result<u32, DosHostError> {
        panic!("unexpected host call")
    }
    fn file_set_len(&mut self, _: DosHostFile, _: u32) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn file_delete(&mut self, _: &[u8]) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn directory_create(&mut self, _: &[u8]) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn directory_remove(&mut self, _: &[u8]) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn directory_set_current(&mut self, _: &[u8]) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn directory_get_current(&mut self, _: u8, _: &mut [u8]) -> Result<usize, DosHostError> {
        panic!("unexpected host call")
    }
    fn file_rename(&mut self, _: &[u8], _: &[u8]) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn file_get_attributes(&mut self, _: &[u8]) -> Result<u8, DosHostError> {
        panic!("unexpected host call")
    }
    fn file_set_attributes(&mut self, _: &[u8], _: u8) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn directory_search_open(&mut self, _: &[u8]) -> Result<DosHostSearch, DosHostError> {
        panic!("unexpected host call")
    }
    fn directory_search_next(
        &mut self,
        _: DosHostSearch,
    ) -> Result<Option<DosDirectoryEntry>, DosHostError> {
        panic!("unexpected host call")
    }
    fn directory_search_close(&mut self, _: DosHostSearch) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn guest_code_page(&self) -> text_codec::CodePage {
        panic!("unexpected host call")
    }
    fn current_drive(&self) -> u8 {
        panic!("unexpected host call")
    }
    fn select_drive(&mut self, _: u8) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn logical_drive_count(&self) -> u8 {
        panic!("unexpected host call")
    }
}

impl RuntimeHost for Host {
    fn win16_gdi_device(&mut self, operation: Operation) -> Result<HostResult, RuntimeError> {
        self.calls.push(operation);
        Ok(HostResult::Count(1))
    }
    fn win16_delete_dc(&mut self, dc: Win16HostDc) -> Result<bool, RuntimeError> {
        assert_eq!(dc, NATIVE);
        Ok(true)
    }
    fn epoch_seconds(&self) -> i64 {
        panic!("unexpected host call")
    }
    fn read_bios_key(&mut self) -> Result<KeyStroke, RuntimeError> {
        panic!("unexpected host call")
    }
    fn render_text(&mut self, _: &ConsoleSnapshot) -> Result<(), RuntimeError> {
        panic!("unexpected host call")
    }
}
impl crate::RuntimeDdeHost for Host {
    fn win16_dde_abort(&mut self) -> crate::Win16DdeAbortReceipt {
        panic!("unexpected host call")
    }
}
impl crate::RuntimeMciHost for Host {}
impl crate::RuntimeMidiHost for Host {}
impl crate::RuntimeNetbiosHost for Host {}

fn fixture(pop: u16) -> (Runtime, u16, u32) {
    let mut runtime = Runtime::load(&tiny_ne_executable(), &[], br"C:\ABORT.NE").unwrap();
    let callback = (u32::from(runtime.cpu.regs.cs) << 16) | 0x80;
    let state = runtime.win16.as_mut().unwrap();
    let pointer = state.selectors.pointer_from_far(callback).unwrap();
    let physical = state
        .selectors
        .translate(pointer, Access::Execute, 3, &runtime.memory)
        .unwrap();
    runtime
        .memory
        .write(physical, &[0xca, pop as u8, (pop >> 8) as u8])
        .unwrap();
    let dc = state.guest_gdi.allocate_dc(NATIVE).unwrap();
    (runtime, dc, callback)
}

fn invoke(runtime: &mut Runtime, ordinal: u16, stack_args: &[u8]) -> (u16, u16, u16) {
    let descriptor = lookup_export(b"GDI", ExportLookupTarget::Ordinal(ordinal)).unwrap();
    let return_cs = runtime.cpu.regs.cs;
    let return_ip = 0x20_u16;
    let stack = runtime.cpu.regs.sp();
    let state = runtime.win16.as_mut().unwrap();
    let mut bytes = Vec::from(return_ip.to_le_bytes());
    bytes.extend_from_slice(&return_cs.to_le_bytes());
    bytes.extend_from_slice(stack_args);
    let pointer = state
        .selectors
        .pointer_from_raw(Selector(runtime.cpu.regs.ss), stack)
        .unwrap();
    state
        .selectors
        .write(&mut runtime.memory, pointer, &bytes)
        .unwrap();
    let slot = state.bindings.len();
    state.bindings.push(ImportBinding::Supported(descriptor));
    runtime.cpu.regs.cs = state.gate_selector.0;
    runtime.cpu.regs.set_ip((slot * 2) as u16);
    runtime.cpu.regs.eax = 0xa1b2_a55a;
    runtime.cpu.regs.edx = 0xc3d4_5aa5;
    (return_cs, return_ip, stack + bytes.len() as u16)
}

fn dispatch(runtime: &mut Runtime, host: &mut Host) -> Result<Option<u8>, RuntimeError> {
    runtime.win16.as_mut().unwrap().dispatch(
        &mut runtime.cpu,
        &mut runtime.memory,
        &mut runtime.dos,
        host,
        0,
    )
}

fn assert_return(runtime: &Runtime, return_to: (u16, u16, u16), result: u16) {
    assert_eq!(runtime.cpu.regs.eax, 0xa1b2_0000 | u32::from(result));
    assert_eq!(runtime.cpu.regs.edx, 0xc3d4_5aa5);
    assert_eq!(
        (
            runtime.cpu.regs.cs,
            runtime.cpu.regs.ip(),
            runtime.cpu.regs.sp()
        ),
        return_to,
    );
}

fn assert_idle(runtime: &Runtime) {
    let state = runtime.win16.as_ref().unwrap();
    assert!(state.print_abort_callbacks.is_empty());
    assert!(state.callback_kinds.is_empty());
    assert!(state.callback_frame_ids.is_empty());
    assert!(state.legacy_cpu_frames.is_empty());
}

fn retf(runtime: &mut Runtime, host: &mut Host) -> Result<(), RuntimeError> {
    let state = runtime.win16.as_mut().unwrap();
    let segments = crate::win16_loader::Win16Segments {
        selectors: &state.selectors,
        memory_len: runtime.memory.len(),
    };
    runtime
        .cpu
        .step_with_context(&mut runtime.memory.bus(), &mut NoPorts, &segments)
        .unwrap();
    assert_eq!(
        runtime.cpu.control_transfer(),
        Some(x86_cpu::ControlTransfer::FarReturn)
    );
    state.finish_callback(
        &mut runtime.cpu,
        &mut runtime.memory,
        &mut runtime.dos,
        host,
    )
}

fn dword_word(dword: u32, word: u16) -> [u8; 6] {
    let mut bytes = [0; 6];
    bytes[..4].copy_from_slice(&dword.to_le_bytes());
    bytes[4..].copy_from_slice(&word.to_le_bytes());
    bytes
}

fn code_dc(code: u16, dc: u16) -> [u8; 4] {
    let mut bytes = [0; 4];
    bytes[..2].copy_from_slice(&code.to_le_bytes());
    bytes[2..].copy_from_slice(&dc.to_le_bytes());
    bytes
}

fn install(runtime: &mut Runtime, host: &mut Host, dc: u16, callback: u32) {
    let return_to = invoke(runtime, 381, &dword_word(callback, dc));
    dispatch(runtime, host).unwrap();
    assert_return(runtime, return_to, 1);
    assert!(host.calls.is_empty());
    assert_eq!(
        runtime.win16.as_ref().unwrap().guest_gdi.abort_proc(dc),
        Some(callback)
    );
    assert!(
        runtime
            .win16
            .as_ref()
            .unwrap()
            .print_abort_code_references()
            .contains(&callback)
    );
}

fn read_callback_args(runtime: &Runtime) -> (u16, u16, u16) {
    let state = runtime.win16.as_ref().unwrap();
    let pointer = state
        .selectors
        .pointer_from_raw(Selector(runtime.cpu.regs.ss), runtime.cpu.regs.sp())
        .unwrap();
    let mut bytes = [0; 8];
    state
        .selectors
        .read(&runtime.memory, pointer, &mut bytes)
        .unwrap();
    let code = u16::from_le_bytes([bytes[4], bytes[5]]);
    let hdc = u16::from_le_bytes([bytes[6], bytes[7]]);
    let gate = u16::from_le_bytes([bytes[2], bytes[3]]);
    assert_eq!(gate, state.callback_gate_selector.0);
    assert_eq!(u16::from_le_bytes([bytes[0], bytes[1]]), 0);
    (hdc, code, gate)
}

#[test]
fn set_abort_proc_rejects_unknown_and_non_executable_targets() {
    let (mut runtime, dc, callback) = fixture(4);
    let mut host = Host::default();
    let return_to = invoke(&mut runtime, 381, &dword_word(callback, 0xffff));
    dispatch(&mut runtime, &mut host).unwrap();
    assert_return(&runtime, return_to, SP_ERROR);
    assert!(
        runtime
            .win16
            .as_ref()
            .unwrap()
            .guest_gdi
            .abort_proc(0xffff)
            .is_none()
    );
    assert!(
        runtime
            .win16
            .as_ref()
            .unwrap()
            .print_abort_code_references()
            .is_empty()
    );

    install(&mut runtime, &mut host, dc, callback);
    let return_to = invoke(&mut runtime, 381, &dword_word(1, dc));
    dispatch(&mut runtime, &mut host).unwrap();
    assert_return(&runtime, return_to, SP_ERROR);
    assert_eq!(
        runtime.win16.as_ref().unwrap().guest_gdi.abort_proc(dc),
        Some(callback)
    );

    let return_to = invoke(&mut runtime, 381, &dword_word(0, dc));
    dispatch(&mut runtime, &mut host).unwrap();
    assert_return(&runtime, return_to, 1);
    assert!(
        runtime
            .win16
            .as_ref()
            .unwrap()
            .guest_gdi
            .abort_proc(dc)
            .is_none()
    );
    assert!(
        !runtime
            .win16
            .as_ref()
            .unwrap()
            .print_abort_code_references()
            .contains(&callback)
    );
    assert_idle(&runtime);
}

#[test]
fn query_abort_enters_the_procedure_and_returns_its_bool_without_canceling() {
    let (mut runtime, dc, callback) = fixture(4);
    let mut host = Host::default();
    let return_to = invoke(&mut runtime, 155, &code_dc(0xfffc, dc));
    dispatch(&mut runtime, &mut host).unwrap();
    assert_return(&runtime, return_to, 1);
    assert!(host.calls.is_empty());

    install(&mut runtime, &mut host, dc, callback);
    let return_to = invoke(&mut runtime, 155, &code_dc(0xfffc, dc));
    dispatch(&mut runtime, &mut host).unwrap();
    assert_eq!(
        (runtime.cpu.regs.cs, runtime.cpu.regs.ip()),
        ((callback >> 16) as u16, callback as u16)
    );
    assert_eq!(
        read_callback_args(&runtime),
        (
            dc,
            0xfffc,
            runtime.win16.as_ref().unwrap().callback_gate_selector.0
        )
    );
    runtime.cpu.regs.set_ax(0);
    runtime.cpu.regs.set_dx(0x1111);
    retf(&mut runtime, &mut host).unwrap();
    assert_return(&runtime, return_to, 0);
    assert!(host.calls.is_empty());
    assert_eq!(
        runtime.win16.as_ref().unwrap().guest_gdi.abort_proc(dc),
        Some(callback)
    );

    let return_to = invoke(&mut runtime, 155, &code_dc(0, dc));
    dispatch(&mut runtime, &mut host).unwrap();
    assert_eq!(read_callback_args(&runtime).1, 0);
    runtime.cpu.regs.set_ax(7);
    retf(&mut runtime, &mut host).unwrap();
    assert_return(&runtime, return_to, 7);
    assert_idle(&runtime);
}

#[test]
fn print_calls_enter_abort_proc_and_skip_the_host_when_it_returns_false() {
    let (mut runtime, dc, callback) = fixture(4);
    let mut host = Host::default();
    install(&mut runtime, &mut host, dc, callback);

    let return_to = invoke(&mut runtime, 379, &dc.to_le_bytes());
    dispatch(&mut runtime, &mut host).unwrap();
    assert_eq!(
        read_callback_args(&runtime),
        (
            dc,
            0,
            runtime.win16.as_ref().unwrap().callback_gate_selector.0
        )
    );
    runtime.cpu.regs.set_ax(0);
    retf(&mut runtime, &mut host).unwrap();
    assert_return(&runtime, return_to, SP_APPABORT);
    assert!(host.calls.is_empty());

    let return_to = invoke(&mut runtime, 379, &dc.to_le_bytes());
    dispatch(&mut runtime, &mut host).unwrap();
    runtime.cpu.regs.set_ax(1);
    retf(&mut runtime, &mut host).unwrap();
    assert_return(&runtime, return_to, 1);
    assert_eq!(
        host.calls,
        [Operation::Print {
            operation: Win16PrintOperation::StartPage,
            dc: NATIVE
        }]
    );

    host.calls.clear();
    let mut escape = Vec::new();
    escape.extend_from_slice(&0u32.to_le_bytes());
    escape.extend_from_slice(&0u32.to_le_bytes());
    escape.extend_from_slice(&0i16.to_le_bytes());
    escape.extend_from_slice(&1i16.to_le_bytes());
    escape.extend_from_slice(&dc.to_le_bytes());
    let return_to = invoke(&mut runtime, 38, &escape);
    dispatch(&mut runtime, &mut host).unwrap();
    assert_eq!(read_callback_args(&runtime).1, 0);
    runtime.cpu.regs.set_ax(0);
    retf(&mut runtime, &mut host).unwrap();
    assert_return(&runtime, return_to, SP_APPABORT);
    assert!(host.calls.is_empty());

    let return_to = invoke(&mut runtime, 38, &escape);
    dispatch(&mut runtime, &mut host).unwrap();
    runtime.cpu.regs.set_ax(1);
    retf(&mut runtime, &mut host).unwrap();
    assert_return(&runtime, return_to, 1);
    assert_eq!(
        host.calls,
        [
            Operation::Print {
                operation: Win16PrintOperation::EndPage,
                dc: NATIVE
            },
            Operation::Print {
                operation: Win16PrintOperation::StartPage,
                dc: NATIVE
            },
        ]
    );
}

#[test]
fn abort_doc_and_a_cleared_procedure_do_not_enter_the_callback() {
    let (mut runtime, dc, callback) = fixture(4);
    let mut host = Host::default();
    install(&mut runtime, &mut host, dc, callback);
    let return_to = invoke(&mut runtime, 382, &dc.to_le_bytes());
    dispatch(&mut runtime, &mut host).unwrap();
    assert_return(&runtime, return_to, 1);
    assert_eq!(
        host.calls,
        [Operation::Print {
            operation: Win16PrintOperation::AbortDocument,
            dc: NATIVE,
        }]
    );
    assert_eq!(
        (runtime.cpu.regs.cs, runtime.cpu.regs.ip()),
        (return_to.0, return_to.1)
    );
    assert_idle(&runtime);
}

#[test]
fn escape_set_abort_proc_installs_the_procedure_and_reports_support() {
    let (mut runtime, dc, callback) = fixture(4);
    let mut host = Host::default();
    let mut escape = Vec::new();
    escape.extend_from_slice(&0u32.to_le_bytes());
    escape.extend_from_slice(&callback.to_le_bytes());
    escape.extend_from_slice(&0i16.to_le_bytes());
    escape.extend_from_slice(&SET_ABORT_PROC_ESCAPE.to_le_bytes());
    escape.extend_from_slice(&dc.to_le_bytes());
    let return_to = invoke(&mut runtime, 38, &escape);
    dispatch(&mut runtime, &mut host).unwrap();
    assert_return(&runtime, return_to, 1);
    assert!(host.calls.is_empty());
    assert_eq!(
        runtime.win16.as_ref().unwrap().guest_gdi.abort_proc(dc),
        Some(callback)
    );

    let output = {
        let state = runtime.win16.as_mut().unwrap();
        let selector = state
            .selectors
            .alloc_block(
                guest_core::PhysAddr(0x70000),
                0x10000,
                win16_abi::AccessRights::read_write(),
                &runtime.memory,
            )
            .unwrap();
        let pointer = win16_abi::SegmentedPointer::new(selector, 0);
        state
            .selectors
            .write(
                &mut runtime.memory,
                pointer,
                &SET_ABORT_PROC_ESCAPE.to_le_bytes(),
            )
            .unwrap();
        pointer.far_value()
    };
    let mut query = Vec::new();
    query.extend_from_slice(&0u32.to_le_bytes());
    query.extend_from_slice(&output.to_le_bytes());
    query.extend_from_slice(&2i16.to_le_bytes());
    query.extend_from_slice(&8i16.to_le_bytes());
    query.extend_from_slice(&dc.to_le_bytes());
    let return_to = invoke(&mut runtime, 38, &query);
    dispatch(&mut runtime, &mut host).unwrap();
    assert_return(&runtime, return_to, 1);
    assert!(host.calls.is_empty());

    let return_to = invoke(&mut runtime, 155, &code_dc(0, dc));
    dispatch(&mut runtime, &mut host).unwrap();
    assert_eq!(
        (runtime.cpu.regs.cs, runtime.cpu.regs.ip()),
        ((callback >> 16) as u16, 0x80)
    );
    runtime.cpu.regs.set_ax(1);
    retf(&mut runtime, &mut host).unwrap();
    assert_return(&runtime, return_to, 1);
}

#[test]
fn bad_retf_and_task_teardown_restore_the_captured_caller() {
    let (mut runtime, dc, callback) = fixture(2);
    let mut host = Host::default();
    install(&mut runtime, &mut host, dc, callback);
    let return_to = invoke(&mut runtime, 155, &code_dc(0, dc));
    let captured = runtime.cpu.regs.clone();
    dispatch(&mut runtime, &mut host).unwrap();
    let error = retf(&mut runtime, &mut host).unwrap_err();
    assert_eq!(error.kind(), Kind::GuestFault);
    assert_eq!(
        runtime.win16.as_ref().unwrap().print_abort_callbacks.len(),
        1
    );
    let ended = super::super::execute::Win16TaskExecutionEnded::for_test();
    runtime
        .win16
        .as_mut()
        .unwrap()
        .cancel_print_abort_callback_for_teardown(
            &ended,
            &mut runtime.cpu,
            &mut runtime.dos,
            &mut runtime.memory,
        )
        .unwrap();
    assert_eq!(runtime.cpu.regs, captured);
    assert_ne!(
        (
            runtime.cpu.regs.cs,
            runtime.cpu.regs.ip(),
            runtime.cpu.regs.sp()
        ),
        return_to
    );
    assert_idle(&runtime);
    assert_eq!(
        runtime.win16.as_ref().unwrap().guest_gdi.abort_proc(dc),
        Some(callback)
    );
}

#[test]
fn short_stack_and_deleted_dc_do_not_enter_or_keep_the_procedure() {
    let (mut runtime, dc, callback) = fixture(4);
    let mut host = Host::default();
    install(&mut runtime, &mut host, dc, callback);
    runtime.cpu.regs.set_sp(6);
    let _ = invoke(&mut runtime, 155, &code_dc(0, dc));
    let before = runtime.cpu.regs.clone();
    let error = dispatch(&mut runtime, &mut host).unwrap_err();
    assert_eq!(error.kind(), Kind::GuestFault);
    assert_eq!(runtime.cpu.regs, before);
    assert_idle(&runtime);
    assert_eq!(
        runtime.win16.as_ref().unwrap().guest_gdi.abort_proc(dc),
        Some(callback)
    );

    assert_eq!(
        runtime
            .win16
            .as_mut()
            .unwrap()
            .delete_dc(dc, &mut host)
            .unwrap(),
        1
    );
    assert!(
        runtime
            .win16
            .as_ref()
            .unwrap()
            .guest_gdi
            .abort_proc(dc)
            .is_none()
    );
    let return_to = invoke(&mut runtime, 155, &code_dc(0, dc));
    dispatch(&mut runtime, &mut host).unwrap();
    assert_return(&runtime, return_to, 0);
    assert_idle(&runtime);
}

fn doc_info(runtime: &mut Runtime) -> u32 {
    let state = runtime.win16.as_mut().unwrap();
    let selector = state
        .selectors
        .alloc_block(
            PhysAddr(0x70000),
            0x10000,
            AccessRights::read_write(),
            &runtime.memory,
        )
        .unwrap();
    let pointer = SegmentedPointer::new(selector, 0);
    let mut bytes = [0; 10];
    bytes[..2].copy_from_slice(&10u16.to_le_bytes());
    state
        .selectors
        .write(&mut runtime.memory, pointer, &bytes)
        .unwrap();
    pointer.far_value()
}

fn started_document() -> Operation {
    Operation::StartDoc {
        dc: NATIVE,
        document_name: None,
        output: None,
    }
}

fn aborted_document() -> Operation {
    Operation::Print {
        operation: Win16PrintOperation::AbortDocument,
        dc: NATIVE,
    }
}

fn reject_print(runtime: &mut Runtime, host: &mut Host, ordinal: u16, args: &[u8]) {
    let return_to = invoke(runtime, ordinal, args);
    dispatch(runtime, host).unwrap();
    runtime.cpu.regs.set_ax(0);
    retf(runtime, host).unwrap();
    assert_return(runtime, return_to, SP_APPABORT);
    assert_idle(runtime);
}

fn accept_start_doc(runtime: &mut Runtime, host: &mut Host, dc: u16, info: u32) {
    let return_to = invoke(runtime, 377, &dword_word(info, dc));
    dispatch(runtime, host).unwrap();
    runtime.cpu.regs.set_ax(1);
    retf(runtime, host).unwrap();
    assert_return(runtime, return_to, 1);
    assert_idle(runtime);
}

#[test]
fn false_abort_after_start_doc_cancels_the_host_document() {
    let (mut runtime, dc, callback) = fixture(4);
    let mut host = Host::default();
    install(&mut runtime, &mut host, dc, callback);
    let info = doc_info(&mut runtime);
    let start_doc = dword_word(info, dc);

    reject_print(&mut runtime, &mut host, 377, &start_doc);
    assert!(host.calls.is_empty());

    accept_start_doc(&mut runtime, &mut host, dc, info);
    assert_eq!(host.calls, [started_document()]);

    let return_to = invoke(&mut runtime, 155, &code_dc(0, dc));
    dispatch(&mut runtime, &mut host).unwrap();
    runtime.cpu.regs.set_ax(0);
    retf(&mut runtime, &mut host).unwrap();
    assert_return(&runtime, return_to, 0);
    assert_eq!(host.calls, [started_document()]);

    reject_print(&mut runtime, &mut host, 379, &dc.to_le_bytes());
    assert_eq!(host.calls, [started_document(), aborted_document()]);
    reject_print(&mut runtime, &mut host, 379, &dc.to_le_bytes());
    assert_eq!(host.calls.len(), 2);

    for (ordinal, args) in [
        (380, dc.to_le_bytes().to_vec()),
        (378, dc.to_le_bytes().to_vec()),
        (38, escape_args(dc, 1)),
        (38, escape_args(dc, 11)),
    ] {
        accept_start_doc(&mut runtime, &mut host, dc, info);
        let before = host.calls.len();
        reject_print(&mut runtime, &mut host, ordinal, &args);
        assert_eq!(
            &host.calls[before - 1..],
            [started_document(), aborted_document()]
        );
    }

    accept_start_doc(&mut runtime, &mut host, dc, info);
    let before = host.calls.len();
    reject_print(&mut runtime, &mut host, 38, &escape_args(dc, 10));
    assert_eq!(host.calls.len(), before);
    reject_print(&mut runtime, &mut host, 379, &dc.to_le_bytes());
    assert_eq!(host.calls.last(), Some(&aborted_document()));

    accept_start_doc(&mut runtime, &mut host, dc, info);
    let return_to = invoke(&mut runtime, 378, &dc.to_le_bytes());
    dispatch(&mut runtime, &mut host).unwrap();
    runtime.cpu.regs.set_ax(1);
    retf(&mut runtime, &mut host).unwrap();
    assert_return(&runtime, return_to, 1);
    assert_eq!(
        host.calls.last(),
        Some(&Operation::Print {
            operation: Win16PrintOperation::EndDocument,
            dc: NATIVE,
        })
    );
    let before = host.calls.len();
    reject_print(&mut runtime, &mut host, 379, &dc.to_le_bytes());
    assert_eq!(host.calls.len(), before);
}

fn escape_args(dc: u16, escape: i16) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&0i16.to_le_bytes());
    bytes.extend_from_slice(&escape.to_le_bytes());
    bytes.extend_from_slice(&dc.to_le_bytes());
    bytes
}

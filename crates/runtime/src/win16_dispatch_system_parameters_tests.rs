//! USER.483 Windows 3.1 actions that were compatibility gaps, plus one unknown.
use super::super::{ImportBinding, test_support::tiny_ne_executable};
use crate::{
    Diagnostic, DiagnosticKind as Kind, Runtime, RuntimeError, RuntimeHost,
    Win16HostSystemParametersResult, Win16HostUserServiceOperation, Win16HostUserServiceResult,
    Win16HostWindowOperationId, Win16NativeWindowOperationKind, Win16NativeWindowOperationProof,
    Win16NativeWindowOperationState, Win16SystemParametersRequest as Request,
    Win16SystemParametersValue as Value, Win16WindowOperation, Win16WindowResult,
    Win16WindowSourceRetiredProof, Win16WindowStep,
};
use devices::{keyboard::KeyStroke, video::ConsoleSnapshot};
use dos_kernel::{
    DosDirectoryEntry, DosFileAccess, DosFileSharing, DosHost, DosHostError, DosHostFile,
    DosHostSearch, DosSeekOrigin,
};
use guest_core::Selector;
use std::sync::Arc;
use win16_abi::{ExportLookupTarget, Win16ExportStackCleanup, Win16ReturnKind, lookup_export};

const ORDINAL: u16 = 483;
const OFFSET: u16 = 0x10;
const AX: u16 = 0xa55a;
const DX: u16 = 0x5aa5;
const SPI_SETDOUBLECLKWIDTH: u16 = 29;
const SPI_SETDOUBLECLKHEIGHT: u16 = 30;
const SPI_SETDOUBLECLICKTIME: u16 = 32;
const SPI_SETMOUSEBUTTONSWAP: u16 = 33;
const SPI_GETFASTTASKSWITCH: u16 = 35;
const SPI_SETFASTTASKSWITCH: u16 = 36;
const SPI_UNNAMED: u16 = 7;

struct SpiHost {
    requests: Vec<Request>,
    succeeded: bool,
    output: Option<bool>,
    diagnostics: Vec<(Kind, String)>,
    consumed: usize,
}

fn proof() -> Arc<Win16WindowSourceRetiredProof> {
    Arc::new(Win16WindowSourceRetiredProof {
        operation: Win16NativeWindowOperationProof {
            operation_id: Win16HostWindowOperationId(41),
            kind: Win16NativeWindowOperationKind::UserService,
        },
        worker_generation: 7,
        state: Win16NativeWindowOperationState::Returned,
    })
}

impl DosHost for SpiHost {
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

impl RuntimeHost for SpiHost {
    fn report_diagnostic(&mut self, diagnostic: &Diagnostic) {
        self.diagnostics.push((diagnostic.kind(), diagnostic.to_string()));
    }
    fn win16_window_begin(&mut self, operation: Win16WindowOperation) -> Result<Win16WindowStep, RuntimeError> {
        let Win16WindowOperation::UserService(Win16HostUserServiceOperation::SystemParameters(request)) = operation else {
            panic!("unexpected host operation");
        };
        self.requests.push(request);
        let proof = proof();
        let value = match self.output {
            Some(value) => Value::Bool(value),
            None => Value::None,
        };
        Ok(Win16WindowStep::Started {
            operation_id: proof.operation.operation_id,
            worker_generation: proof.worker_generation,
            kind: proof.operation.kind,
            step: Box::new(Win16WindowStep::SourceRetired {
                proof,
                result: Box::new(Win16WindowStep::Complete(Win16WindowResult::UserService(
                    Win16HostUserServiceResult::SystemParameters(Win16HostSystemParametersResult {
                        succeeded: self.succeeded,
                        value,
                    }),
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
impl crate::RuntimeDdeHost for SpiHost {
    fn win16_dde_abort(&mut self) -> crate::Win16DdeAbortReceipt { panic!("unexpected host call") }
}
impl crate::RuntimeMciHost for SpiHost {}
impl crate::RuntimeMidiHost for SpiHost {}
impl crate::RuntimeNetbiosHost for SpiHost {}

fn fixture() -> Runtime {
    let mut runtime = Runtime::load(&tiny_ne_executable(), &[], br"C:\SPI.NE").unwrap();
    let state = runtime.win16.as_ref().unwrap();
    let pointer = state.selectors.pointer_from_raw(Selector(runtime.cpu.regs.ds), OFFSET - 2).unwrap();
    state.selectors.write(&mut runtime.memory, pointer, &[0xa7; 6]).unwrap();
    runtime
}

fn far(runtime: &Runtime) -> u32 {
    (u32::from(runtime.cpu.regs.ds) << 16) | u32::from(OFFSET)
}

fn bytes(runtime: &Runtime) -> [u8; 6] {
    let state = runtime.win16.as_ref().unwrap();
    let pointer = state.selectors.pointer_from_raw(Selector(runtime.cpu.regs.ds), OFFSET - 2).unwrap();
    let mut bytes = [0; 6];
    state.selectors.read(&runtime.memory, pointer, &mut bytes).unwrap();
    bytes
}

fn prepare(runtime: &mut Runtime, action: u16, param: u16, data: u32, flags: u16) -> (u16, u16, u16) {
    let descriptor = lookup_export(b"USER", ExportLookupTarget::Ordinal(ORDINAL)).unwrap();
    assert_eq!(descriptor.return_kind, Win16ReturnKind::Word);
    let Win16ExportStackCleanup::Fixed(cleanup) = descriptor.stack_cleanup else {
        panic!("SystemParametersInfo requires a fixed Pascal frame");
    };
    assert_eq!((cleanup.callee_pop_bytes, cleanup.caller_pop_bytes), (10, 0));
    let return_cs = runtime.cpu.regs.cs;
    let return_ip = 0x12_u16;
    let stack = runtime.cpu.regs.sp();
    let state = runtime.win16.as_mut().unwrap();
    let mut frame = Vec::from(return_ip.to_le_bytes());
    frame.extend_from_slice(&return_cs.to_le_bytes());
    frame.extend_from_slice(&flags.to_le_bytes());
    frame.extend_from_slice(&data.to_le_bytes());
    frame.extend_from_slice(&param.to_le_bytes());
    frame.extend_from_slice(&action.to_le_bytes());
    let pointer = state.selectors.pointer_from_raw(Selector(runtime.cpu.regs.ss), stack).unwrap();
    state.selectors.write(&mut runtime.memory, pointer, &frame).unwrap();
    let slot = state.bindings.len();
    state.bindings.push(ImportBinding::Supported(descriptor));
    runtime.cpu.regs.cs = state.gate_selector.0;
    runtime.cpu.regs.set_ip((slot * 2) as u16);
    runtime.cpu.regs.set_ax(AX);
    runtime.cpu.regs.set_dx(DX);
    (return_cs, return_ip, stack + frame.len() as u16)
}

fn dispatch(runtime: &mut Runtime, host: &mut SpiHost) -> Result<Option<u8>, RuntimeError> {
    runtime.win16.as_mut().unwrap().dispatch(
        &mut runtime.cpu, &mut runtime.memory, &mut runtime.dos, host, 0,
    )
}

fn assert_return(runtime: &Runtime, return_to: (u16, u16, u16), value: u16) {
    assert_eq!(runtime.cpu.regs.ax(), value);
    assert_eq!(runtime.cpu.regs.dx(), DX);
    assert_eq!((runtime.cpu.regs.cs, runtime.cpu.regs.ip(), runtime.cpu.regs.sp()), return_to);
    assert!(runtime.win16.as_ref().unwrap().window_operations.is_empty());
}

fn call(action: u16, param: u16, data: bool, flags: u16, host: SpiHost) -> (u16, [u8; 6], SpiHost) {
    let mut runtime = fixture();
    let pointer = if data { far(&runtime) } else { 0 };
    let return_to = prepare(&mut runtime, action, param, pointer, flags);
    let mut host = host;
    dispatch(&mut runtime, &mut host).unwrap();
    assert_return(&runtime, return_to, runtime.cpu.regs.ax());
    (runtime.cpu.regs.ax(), bytes(&runtime), host)
}

#[test]
fn spi_windows31_word_setters_forward_the_guest_word_and_flags() {
    for action in [SPI_SETDOUBLECLKWIDTH, SPI_SETDOUBLECLKHEIGHT, SPI_SETDOUBLECLICKTIME] {
        for param in [0, 500, u16::MAX] {
            for flags in [0, 0x0003] {
                for succeeded in [false, true] {
                    for data in [false, true] {
                        let (ax, guest, host) = call(action, param, data, flags, SpiHost {
                            requests: Vec::new(), succeeded, output: None,
                            diagnostics: Vec::new(), consumed: 0,
                        });
                        assert_eq!(ax, u16::from(succeeded));
                        assert_eq!(guest, [0xa7; 6]);
                        assert!(host.diagnostics.is_empty());
                        assert_eq!(host.consumed, 1);
                        assert_eq!(host.requests, [Request::SetWord { action, value: param, flags }]);
                    }
                }
            }
        }
    }
}

#[test]
fn spi_windows31_bool_setters_map_nonzero_to_true() {
    for action in [SPI_SETMOUSEBUTTONSWAP, SPI_SETFASTTASKSWITCH] {
        for param in [0, 1, 2, 0x8000] {
            for flags in [0, 0x0001] {
                let (ax, guest, host) = call(action, param, true, flags, SpiHost {
                    requests: Vec::new(), succeeded: true, output: None,
                    diagnostics: Vec::new(), consumed: 0,
                });
                assert_eq!(ax, 1);
                assert_eq!(guest, [0xa7; 6]);
                assert!(host.diagnostics.is_empty());
                assert_eq!(host.requests, [Request::SetBool {
                    action, value: param != 0, flags,
                }]);
            }
        }
        let (ax, guest, host) = call(action, 1, false, 0, SpiHost {
            requests: Vec::new(), succeeded: false, output: None,
            diagnostics: Vec::new(), consumed: 0,
        });
        assert_eq!(ax, 0);
        assert_eq!(guest, [0xa7; 6]);
        assert_eq!(host.requests, [Request::SetBool { action, value: true, flags: 0 }]);
    }
}

#[test]
fn spi_get_fast_task_switch_writes_a_guest_bool() {
    for (output, succeeded, expected) in [
        (Some(true), true, [0xa7, 0xa7, 0x01, 0x00, 0xa7, 0xa7]),
        (Some(false), true, [0xa7, 0xa7, 0x00, 0x00, 0xa7, 0xa7]),
        (Some(true), false, [0xa7; 6]),
    ] {
        for param in [0, 0xabcd] {
            let (ax, guest, host) = call(SPI_GETFASTTASKSWITCH, param, true, 0x0002, SpiHost {
                requests: Vec::new(), succeeded, output, diagnostics: Vec::new(), consumed: 0,
            });
            assert_eq!(ax, u16::from(succeeded));
            assert_eq!(guest, expected);
            assert!(host.diagnostics.is_empty());
            assert_eq!(host.consumed, 1);
            assert_eq!(host.requests, [Request::GetBool(SPI_GETFASTTASKSWITCH)]);
        }
    }
    let (ax, guest, host) = call(SPI_GETFASTTASKSWITCH, 0, false, 0, SpiHost {
        requests: Vec::new(), succeeded: true, output: Some(true),
        diagnostics: Vec::new(), consumed: 0,
    });
    assert_eq!(ax, 0);
    assert_eq!(guest, [0xa7; 6]);
    assert!(host.requests.is_empty());
    assert!(host.diagnostics.is_empty());
    assert_eq!(host.consumed, 0);
}

#[test]
fn spi_unnamed_action_remains_a_compatibility_gap() {
    for data in [Some(true), None] {
        let mut runtime = fixture();
        let pointer = match data {
            Some(true) => far(&runtime),
            None => 0xffff_ffff,
            Some(false) => 0,
        };
        let return_to = prepare(&mut runtime, SPI_UNNAMED, 1, pointer, 0x0003);
        let mut host = SpiHost {
            requests: Vec::new(), succeeded: true, output: Some(true),
            diagnostics: Vec::new(), consumed: 0,
        };
        dispatch(&mut runtime, &mut host).unwrap();
        assert_return(&runtime, return_to, 0);
        assert_eq!(bytes(&runtime), [0xa7; 6]);
        assert!(host.requests.is_empty());
        assert_eq!(host.consumed, 0);
        assert_eq!(host.diagnostics.len(), 1);
        assert_eq!(host.diagnostics[0].0, Kind::CompatibilityGap);
        assert!(host.diagnostics[0].1.contains("0x0007"));
    }
}

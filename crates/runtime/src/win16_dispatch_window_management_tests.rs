//! USER.184, 188, 189, 198, 199, 281, and 284.
//!
//! Cascade and tile submit the live `mdi_children` of one parent. The fake
//! host applies the same iconic, hidden, and skip-disabled filter as the
//! Windows host. QuerySendMessage uses the host InSendMessage BOOL and the
//! guest callback payload. System-modal, brush, and free-resource calls do
//! not enter the host.

use super::super::{
    CallbackFrameId, ImportBinding,
    test_support::tiny_ne_executable,
    window_payloads::GuestWindowPayload,
    windows::{WindowCallbackContinuation, WindowCallbackFrame, WindowClassRoot},
};
use crate::{
    DiagnosticKind as Kind, MDITILE_HORIZONTAL, MDITILE_SKIPDISABLED, Runtime, RuntimeError,
    RuntimeHost, Win16ArrangeChild, Win16ChildArrangeMode, Win16HostWindow,
    Win16HostWindowOperationId, Win16MessageCall, Win16MessageCallResult,
    Win16NativeWindowOperationKind, Win16NativeWindowOperationProof,
    Win16NativeWindowOperationState, Win16WindowCall, Win16WindowCallResult, Win16WindowOperation,
    Win16WindowResult, Win16WindowSourceRetiredProof, Win16WindowStep,
};
use devices::{keyboard::KeyStroke, video::ConsoleSnapshot};
use dos_kernel::{
    DosDirectoryEntry, DosFileAccess, DosFileSharing, DosHost, DosHostError, DosHostFile,
    DosHostSearch, DosSeekOrigin,
};
use guest_core::{GuestMemory, Selector};
use std::sync::Arc;
use win16_abi::{ExportLookupTarget, Win16ExportStackCleanup, Win16ReturnKind, lookup_export};

const AX: u16 = 0xa55a;
const DX: u16 = 0x5aa5;
const PARENT: u16 = 0x1000;
const ICONIC: u16 = 0x1001;
const OVERLAPPED: u16 = 0x1002;
const HIDDEN: u16 = 0x1003;
const DISABLED: u16 = 0x1004;
const NON_MDI: u16 = 0x1005;
const OTHER_PARENT: u16 = 0x1006;
const OTHER_CHILD: u16 = 0x1007;
const MSG_OFFSET: u16 = 0x110;

#[derive(Clone, Debug, PartialEq, Eq)]
struct Arranged {
    parent: Win16HostWindow,
    submitted: Vec<Win16HostWindow>,
    flags: u16,
    mode: Win16ChildArrangeMode,
    arranged: Vec<Win16HostWindow>,
}

struct ManagementHost {
    arranged: Vec<Arranged>,
    query_calls: usize,
    in_send: bool,
    time: u32,
    x: i16,
    y: i16,
    kind: Win16NativeWindowOperationKind,
    consumed: usize,
}

impl Default for ManagementHost {
    fn default() -> Self {
        Self {
            arranged: Vec::new(),
            query_calls: 0,
            in_send: false,
            time: 0,
            x: 0,
            y: 0,
            kind: Win16NativeWindowOperationKind::WindowCall,
            consumed: 0,
        }
    }
}

fn proof(kind: Win16NativeWindowOperationKind) -> Arc<Win16WindowSourceRetiredProof> {
    Arc::new(Win16WindowSourceRetiredProof {
        operation: Win16NativeWindowOperationProof {
            operation_id: Win16HostWindowOperationId(41),
            kind,
        },
        worker_generation: 7,
        state: Win16NativeWindowOperationState::Returned,
    })
}

fn child_facts(window: Win16HostWindow) -> (bool, bool, bool) {
    match window.0 as u16 {
        ICONIC => (true, true, true),
        HIDDEN => (false, true, false),
        DISABLED => (false, false, true),
        OVERLAPPED => (false, true, true),
        _ => panic!("arrange host saw an unexpected child"),
    }
}

impl DosHost for ManagementHost {
    fn read_stdin(&mut self, _output: &mut [u8]) -> Result<usize, DosHostError> {
        panic!("unexpected host call")
    }
    fn try_read_stdin(&mut self) -> Result<Option<u8>, DosHostError> {
        panic!("unexpected host call")
    }
    fn write_stdout(&mut self, _input: &[u8]) -> Result<usize, DosHostError> {
        panic!("unexpected host call")
    }
    fn write_stderr(&mut self, _input: &[u8]) -> Result<usize, DosHostError> {
        panic!("unexpected host call")
    }
    fn flush_stdin(&mut self) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn file_create(&mut self, _path: &[u8], _attributes: u8) -> Result<DosHostFile, DosHostError> {
        panic!("unexpected host call")
    }
    fn file_open(
        &mut self,
        _path: &[u8],
        _access: DosFileAccess,
    ) -> Result<DosHostFile, DosHostError> {
        panic!("unexpected host call")
    }
    fn file_open_with_sharing(
        &mut self,
        _path: &[u8],
        _access: DosFileAccess,
        _sharing: DosFileSharing,
    ) -> Result<DosHostFile, DosHostError> {
        panic!("unexpected host call")
    }
    fn file_duplicate(&mut self, _file: DosHostFile) -> Result<DosHostFile, DosHostError> {
        panic!("unexpected host call")
    }
    fn file_close(&mut self, _file: DosHostFile) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn file_read(&mut self, _file: DosHostFile, _output: &mut [u8]) -> Result<usize, DosHostError> {
        panic!("unexpected host call")
    }
    fn file_write(&mut self, _file: DosHostFile, _input: &[u8]) -> Result<usize, DosHostError> {
        panic!("unexpected host call")
    }
    fn file_seek(
        &mut self,
        _file: DosHostFile,
        _offset: i32,
        _origin: DosSeekOrigin,
    ) -> Result<u32, DosHostError> {
        panic!("unexpected host call")
    }
    fn file_set_len(&mut self, _file: DosHostFile, _length: u32) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn file_delete(&mut self, _path: &[u8]) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn directory_create(&mut self, _path: &[u8]) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn directory_remove(&mut self, _path: &[u8]) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn directory_set_current(&mut self, _path: &[u8]) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn directory_get_current(
        &mut self,
        _drive: u8,
        _output: &mut [u8],
    ) -> Result<usize, DosHostError> {
        panic!("unexpected host call")
    }
    fn file_rename(&mut self, _old_path: &[u8], _new_path: &[u8]) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn file_get_attributes(&mut self, _path: &[u8]) -> Result<u8, DosHostError> {
        panic!("unexpected host call")
    }
    fn file_set_attributes(&mut self, _path: &[u8], _attributes: u8) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn directory_search_open(&mut self, _directory: &[u8]) -> Result<DosHostSearch, DosHostError> {
        panic!("unexpected host call")
    }
    fn directory_search_next(
        &mut self,
        _search: DosHostSearch,
    ) -> Result<Option<DosDirectoryEntry>, DosHostError> {
        panic!("unexpected host call")
    }
    fn directory_search_close(&mut self, _search: DosHostSearch) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn guest_code_page(&self) -> text_codec::CodePage {
        panic!("unexpected host call")
    }
    fn current_drive(&self) -> u8 {
        panic!("unexpected host call")
    }
    fn select_drive(&mut self, _drive: u8) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn logical_drive_count(&self) -> u8 {
        panic!("unexpected host call")
    }
}

impl RuntimeHost for ManagementHost {
    fn win16_window_begin(
        &mut self,
        operation: Win16WindowOperation,
    ) -> Result<Win16WindowStep, RuntimeError> {
        let (kind, result) = match operation {
            Win16WindowOperation::WindowCall(Win16WindowCall::ArrangeChildWindows {
                parent,
                children,
                flags,
                mode,
            }) => {
                let arranged = children
                    .iter()
                    .copied()
                    .filter(|window| {
                        let (iconic, enabled, visible) = child_facts(*window);
                        Win16ArrangeChild {
                            window: *window,
                            iconic,
                            enabled,
                            visible,
                        }
                        .participates(flags)
                    })
                    .collect::<Vec<_>>();
                let count = arranged.len() as i32;
                self.arranged.push(Arranged {
                    parent,
                    submitted: children,
                    flags,
                    mode,
                    arranged,
                });
                (
                    Win16NativeWindowOperationKind::WindowCall,
                    Win16WindowResult::WindowCall(Win16WindowCallResult::Integer(count)),
                )
            }
            Win16WindowOperation::MessageCall(Win16MessageCall::QuerySendMessage) => {
                self.query_calls += 1;
                (
                    Win16NativeWindowOperationKind::MessageCall,
                    Win16WindowResult::MessageCall(Win16MessageCallResult::QuerySend {
                        in_send: self.in_send,
                        time: self.time,
                        x: self.x,
                        y: self.y,
                    }),
                )
            }
            _ => panic!("unexpected host operation"),
        };
        self.kind = kind;
        let proof = proof(self.kind);
        Ok(Win16WindowStep::Started {
            operation_id: proof.operation.operation_id,
            worker_generation: proof.worker_generation,
            kind: proof.operation.kind,
            step: Box::new(Win16WindowStep::SourceRetired {
                proof,
                result: Box::new(Win16WindowStep::Complete(result)),
            }),
        })
    }
    fn win16_window_source_retirement(
        &mut self,
        operation: Win16NativeWindowOperationProof,
        worker_generation: u64,
    ) -> Result<Option<Arc<Win16WindowSourceRetiredProof>>, RuntimeError> {
        let proof = proof(self.kind);
        assert_eq!(operation, proof.operation);
        assert_eq!(worker_generation, proof.worker_generation);
        Ok(Some(proof))
    }
    fn win16_window_source_retirement_consumed(
        &mut self,
        actual: &Win16WindowSourceRetiredProof,
    ) -> Result<(), RuntimeError> {
        assert_eq!(actual, proof(self.kind).as_ref());
        self.consumed += 1;
        Ok(())
    }
    fn epoch_seconds(&self) -> i64 {
        panic!("unexpected host call")
    }
    fn read_bios_key(&mut self) -> Result<KeyStroke, RuntimeError> {
        panic!("unexpected host call")
    }
    fn render_text(&mut self, _screen: &ConsoleSnapshot) -> Result<(), RuntimeError> {
        panic!("unexpected host call")
    }
}
impl crate::RuntimeDdeHost for ManagementHost {
    fn win16_dde_abort(&mut self) -> crate::Win16DdeAbortReceipt {
        panic!("unexpected host call")
    }
}
impl crate::RuntimeMciHost for ManagementHost {}
impl crate::RuntimeMidiHost for ManagementHost {}
impl crate::RuntimeNetbiosHost for ManagementHost {}

fn fixture(path: &[u8]) -> Runtime {
    let runtime = Runtime::load(&tiny_ne_executable(), &[], path).unwrap();
    assert!(runtime.memory.len() >= 1024 * 1024);
    runtime
}

fn native(guest: u16) -> Win16HostWindow {
    Win16HostWindow(u64::from(guest))
}

fn map_window(runtime: &mut Runtime, guest: u16, parent: Option<u16>, mdi: bool) {
    let state = runtime.win16.as_mut().unwrap();
    state.window_handles.insert(guest, native(guest));
    if let Some(parent) = parent {
        state.window_parents.insert(guest, parent);
    }
    if mdi {
        state.mdi_children.insert(guest);
    }
}

fn family(runtime: &mut Runtime) {
    map_window(runtime, PARENT, None, false);
    for child in [ICONIC, OVERLAPPED, HIDDEN, DISABLED] {
        map_window(runtime, child, Some(PARENT), true);
    }
    map_window(runtime, NON_MDI, Some(PARENT), false);
    map_window(runtime, OTHER_PARENT, None, false);
    map_window(runtime, OTHER_CHILD, Some(OTHER_PARENT), true);
}

fn prepare(runtime: &mut Runtime, ordinal: u16, args_low_to_high: &[u8]) -> (u16, u16, u16) {
    let descriptor = lookup_export(b"USER", ExportLookupTarget::Ordinal(ordinal)).unwrap();
    assert_eq!(descriptor.return_kind, Win16ReturnKind::Word);
    let Win16ExportStackCleanup::Fixed(cleanup) = descriptor.stack_cleanup else {
        panic!("window-management exports use fixed Pascal cleanup");
    };
    assert_eq!(
        usize::from(cleanup.callee_pop_bytes),
        args_low_to_high.len()
    );
    assert_eq!(cleanup.caller_pop_bytes, 0);
    let return_cs = runtime.cpu.regs.cs;
    let return_ip = 0x12_u16;
    let stack = runtime.cpu.regs.sp();
    let state = runtime.win16.as_mut().unwrap();
    let mut bytes = Vec::from(return_ip.to_le_bytes());
    bytes.extend_from_slice(&return_cs.to_le_bytes());
    bytes.extend_from_slice(args_low_to_high);
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
    runtime.cpu.regs.set_ax(AX);
    runtime.cpu.regs.set_dx(DX);
    (return_cs, return_ip, stack + bytes.len() as u16)
}

fn words_pascal(words_first_to_last: &[u16]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for word in words_first_to_last.iter().rev() {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    bytes
}

fn dispatch(runtime: &mut Runtime, host: &mut ManagementHost) -> Result<Option<u8>, RuntimeError> {
    runtime.win16.as_mut().unwrap().dispatch(
        &mut runtime.cpu,
        &mut runtime.memory,
        &mut runtime.dos,
        host,
        0,
    )
}

fn assert_return(runtime: &Runtime, return_to: (u16, u16, u16), value: u16) {
    assert_eq!(runtime.cpu.regs.ax(), value);
    assert_eq!(runtime.cpu.regs.dx(), DX, "WORD result preserves DX");
    assert_eq!(
        (
            runtime.cpu.regs.cs,
            runtime.cpu.regs.ip(),
            runtime.cpu.regs.sp()
        ),
        return_to
    );
    assert!(runtime.win16.as_ref().unwrap().window_operations.is_empty());
}

fn call(runtime: &mut Runtime, host: &mut ManagementHost, ordinal: u16, args: &[u8]) -> u16 {
    let return_to = prepare(runtime, ordinal, args);
    dispatch(runtime, host).unwrap_or_else(|error| panic!("{error:?}"));
    let value = runtime.cpu.regs.ax();
    assert_return(runtime, return_to, value);
    value
}

#[test]
fn window_management_word_widths_match_the_sdk_frames() {
    for (ordinal, name, bytes) in [
        (184, b"QuerySendMessage".as_slice(), 10),
        (188, b"SetSysModalWindow".as_slice(), 2),
        (189, b"GetSysModalWindow".as_slice(), 0),
        (198, b"CascadeChildWindows".as_slice(), 4),
        (199, b"TileChildWindows".as_slice(), 4),
        (281, b"GetSysColorBrush".as_slice(), 2),
        (284, b"GetFreeSystemResources".as_slice(), 2),
    ] {
        let descriptor = lookup_export(b"USER", ExportLookupTarget::Ordinal(ordinal)).unwrap();
        assert_eq!(
            descriptor.id,
            lookup_export(b"USER", ExportLookupTarget::Name(name))
                .unwrap()
                .id
        );
        assert_eq!(descriptor.return_kind, Win16ReturnKind::Word);
        let Win16ExportStackCleanup::Fixed(cleanup) = descriptor.stack_cleanup else {
            panic!("{name:?} must use fixed Pascal cleanup");
        };
        assert_eq!(cleanup.callee_pop_bytes, bytes);
        assert_eq!(cleanup.caller_pop_bytes, 0);
    }
}

#[test]
fn cascade_and_tile_arrange_only_participating_mdi_children() {
    let mut runtime = fixture(br"C:\ARRANGE.NE");
    family(&mut runtime);
    let mut host = ManagementHost::default();
    let submitted = [
        native(ICONIC),
        native(OVERLAPPED),
        native(HIDDEN),
        native(DISABLED),
    ];

    assert_eq!(
        call(&mut runtime, &mut host, 198, &words_pascal(&[PARENT, 0])),
        2
    );
    assert_eq!(host.arranged.len(), 1);
    assert_eq!(host.arranged[0].parent, native(PARENT));
    assert_eq!(host.arranged[0].submitted, submitted);
    assert_eq!(host.arranged[0].mode, Win16ChildArrangeMode::Cascade);
    assert_eq!(host.arranged[0].flags, 0);
    assert_eq!(
        host.arranged[0].arranged,
        [native(OVERLAPPED), native(DISABLED)]
    );
    assert_eq!(host.consumed, 1);

    assert_eq!(
        call(
            &mut runtime,
            &mut host,
            198,
            &words_pascal(&[PARENT, MDITILE_SKIPDISABLED])
        ),
        1,
    );
    assert_eq!(host.arranged[1].arranged, [native(OVERLAPPED)]);
    assert_eq!(host.arranged[1].flags, MDITILE_SKIPDISABLED);

    let tile_flags = MDITILE_HORIZONTAL | MDITILE_SKIPDISABLED | 0x8000;
    assert_eq!(
        call(
            &mut runtime,
            &mut host,
            199,
            &words_pascal(&[PARENT, tile_flags])
        ),
        1
    );
    assert_eq!(host.arranged[2].mode, Win16ChildArrangeMode::Tile);
    assert_eq!(host.arranged[2].flags, tile_flags);
    assert_eq!(host.arranged[2].submitted, submitted);
    assert_eq!(host.arranged[2].arranged, [native(OVERLAPPED)]);
    assert_eq!(host.consumed, 3);

    for (ordinal, window) in [(198, 0_u16), (198, 0xdead), (199, PARENT)] {
        let before = host.arranged.len();
        let args = if window == PARENT {
            map_window(&mut runtime, 0x1008, Some(PARENT), false);
            words_pascal(&[0x1008, 0])
        } else {
            words_pascal(&[window, 0])
        };
        assert_eq!(call(&mut runtime, &mut host, ordinal, &args), 0);
        assert_eq!(host.arranged.len(), before);
    }
}

#[test]
fn sysmodal_brush_and_free_resources_stay_in_guest_state() {
    let mut runtime = fixture(br"C:\SYSMODAL.NE");
    family(&mut runtime);
    let mut host = ManagementHost::default();

    assert_eq!(
        call(&mut runtime, &mut host, 188, &words_pascal(&[PARENT])),
        0
    );
    assert_eq!(call(&mut runtime, &mut host, 189, &[]), PARENT);
    assert_eq!(
        call(&mut runtime, &mut host, 188, &words_pascal(&[OVERLAPPED])),
        PARENT
    );
    assert_eq!(
        call(&mut runtime, &mut host, 188, &words_pascal(&[0xdead])),
        0
    );
    assert_eq!(call(&mut runtime, &mut host, 189, &[]), OVERLAPPED);
    assert_eq!(
        call(&mut runtime, &mut host, 188, &words_pascal(&[0])),
        OVERLAPPED
    );
    assert_eq!(call(&mut runtime, &mut host, 189, &[]), 0);
    assert_eq!(
        call(&mut runtime, &mut host, 188, &words_pascal(&[PARENT])),
        0
    );
    runtime
        .win16
        .as_mut()
        .unwrap()
        .retire_window_handle(PARENT)
        .unwrap();
    assert_eq!(call(&mut runtime, &mut host, 189, &[]), 0);
    assert!(host.arranged.is_empty());
    assert_eq!(host.query_calls, 0);

    for (index, brush) in [(0_i16, 1_u16), (20, 21), (21, 0), (-1, 0)] {
        assert_eq!(
            call(&mut runtime, &mut host, 281, &words_pascal(&[index as u16])),
            brush
        );
    }
    for (selector, percent) in [(0_u16, 90_u16), (1, 90), (2, 90), (3, 0), (0xffff, 0)] {
        assert_eq!(
            call(&mut runtime, &mut host, 284, &words_pascal(&[selector])),
            percent
        );
    }
}

fn message_fixture() -> Runtime {
    let mut image = tiny_ne_executable();
    image[0x8e..0x90].copy_from_slice(&0x400_u16.to_le_bytes());
    let mut runtime = Runtime::load(&image, &[], br"C:\QUERY.NE").unwrap();
    let state = runtime.win16.as_ref().unwrap();
    let pointer = state
        .selectors
        .pointer_from_raw(Selector(runtime.cpu.regs.ds), MSG_OFFSET - 1)
        .unwrap();
    state
        .selectors
        .write(&mut runtime.memory, pointer, &[0xa7; 20])
        .unwrap();
    runtime
}

fn message_far(runtime: &Runtime) -> u32 {
    (u32::from(runtime.cpu.regs.ds) << 16) | u32::from(MSG_OFFSET)
}

fn message_bytes(runtime: &Runtime) -> [u8; 20] {
    let state = runtime.win16.as_ref().unwrap();
    let pointer = state
        .selectors
        .pointer_from_raw(Selector(runtime.cpu.regs.ds), MSG_OFFSET - 1)
        .unwrap();
    let mut bytes = [0; 20];
    state
        .selectors
        .read(&runtime.memory, pointer, &mut bytes)
        .unwrap();
    bytes
}

fn query_args(message: u32) -> Vec<u8> {
    let mut bytes = message.to_le_bytes().to_vec();
    bytes.extend_from_slice(&words_pascal(&[0x1111, 0x2222, 0x3333]));
    bytes
}

fn push_callback(runtime: &mut Runtime, continuation: WindowCallbackContinuation, message: u16) {
    let saved = runtime.cpu.regs.clone();
    let state = runtime.win16.as_mut().unwrap();
    state.window_callbacks.push(WindowCallbackFrame::guest(
        CallbackFrameId(1),
        saved,
        GuestWindowPayload {
            message,
            w_param: 0x4455,
            l_param: 0x6677_8899,
            allocation: None,
            output: None,
            callback_dc: None,
            command_control: None,
            command_parent: None,
            common_dialog_request: None,
        },
        None,
        0,
        WindowClassRoot::NoRegistration,
        None,
        None,
        continuation,
    ));
}

fn sent_callback(window: u16) -> WindowCallbackContinuation {
    WindowCallbackContinuation::Host {
        callback: crate::Win16HostCallback(1),
        native_window: native(window),
        window,
        destroyed: false,
    }
}

#[test]
fn query_send_message_follows_insend_inside_and_outside_send() {
    let sentinel = [0xa7; 20];
    let mut runtime = message_fixture();
    let message = message_far(&runtime);
    let mut host = ManagementHost {
        in_send: false,
        ..ManagementHost::default()
    };
    assert_eq!(call(&mut runtime, &mut host, 184, &query_args(message)), 0);
    assert_eq!(message_bytes(&runtime), sentinel);
    assert_eq!(host.query_calls, 1);

    push_callback(&mut runtime, sent_callback(OVERLAPPED), 0x0111);
    host.in_send = true;
    host.time = 0x0102_0304;
    host.x = -7;
    host.y = 9;
    assert_eq!(call(&mut runtime, &mut host, 184, &query_args(message)), 1);
    let filled = message_bytes(&runtime);
    assert_eq!(filled[0], 0xa7);
    assert_eq!(filled[19], 0xa7);
    let msg = win16_abi::Msg16::decode(filled[1..19].try_into().unwrap());
    assert_eq!(msg.hwnd, OVERLAPPED);
    assert_eq!(msg.message, 0x0111);
    assert_eq!(msg.w_param, 0x4455);
    assert_eq!(msg.l_param, 0x6677_8899);
    assert_eq!(msg.time, 0x0102_0304);
    assert_eq!((msg.pt.x, msg.pt.y), (-7, 9));

    host.in_send = false;
    assert_eq!(call(&mut runtime, &mut host, 184, &query_args(message)), 0);
    assert_eq!(
        message_bytes(&runtime),
        filled,
        "a false InSendMessage leaves MSG unchanged"
    );

    host.in_send = true;
    assert_eq!(call(&mut runtime, &mut host, 184, &query_args(0)), 1);
    assert_eq!(
        message_bytes(&runtime),
        filled,
        "a null LPMSG is not written"
    );

    runtime.win16.as_mut().unwrap().window_callbacks.clear();
    push_callback(
        &mut runtime,
        WindowCallbackContinuation::GuestDispatch,
        0x0001,
    );
    assert_eq!(call(&mut runtime, &mut host, 184, &query_args(message)), 1);
    assert_eq!(
        message_bytes(&runtime),
        filled,
        "posted dispatch is not a sent message"
    );
    assert_eq!(host.consumed, host.query_calls);
    assert!(host.arranged.is_empty());
}

#[test]
fn query_send_message_rejects_an_invalid_output_before_the_host() {
    let mut runtime = message_fixture();
    let mut host = ManagementHost {
        in_send: true,
        ..ManagementHost::default()
    };
    prepare(&mut runtime, 184, &query_args(u32::MAX));
    assert_eq!(
        dispatch(&mut runtime, &mut host).unwrap_err().kind(),
        Kind::GuestFault
    );
    assert_eq!(host.query_calls, 0);
    assert_eq!(message_bytes(&runtime), [0xa7; 20]);
}

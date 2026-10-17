//! Dialog-frame results for CTL3D/CTL3DV2 ordinal 20.

use super::super::ImportBinding;
use super::super::test_support::tiny_ne_executable;
use super::{DIALOG_FRAME_STYLE, WM_NCACTIVATE, ctl3d_dialog_frame_result};
use crate::{
    Diagnostic, Runtime, RuntimeError, RuntimeHost, Win16HostCtl3dFrameFacts, Win16HostWindow,
};
use devices::{keyboard::KeyStroke, video::ConsoleSnapshot};
use dos_kernel::{
    DosDirectoryEntry, DosFileAccess, DosFileSharing, DosHost, DosHostError, DosHostFile,
    DosHostSearch, DosSeekOrigin,
};
use guest_core::Selector;
use win16_abi::{
    ExportLookupTarget, Win16Ctl3dArgument, Win16Ctl3dModule, Win16Ctl3dRequest, Win16ReturnKind,
    lookup_export,
};

const WINDOW: u16 = 0x0100;
const TOKEN: Win16HostWindow = Win16HostWindow(4);
const WM_SETTEXT: u16 = 0x000c;

fn frame_style() -> u32 {
    DIALOG_FRAME_STYLE
}

#[test]
fn dialog_frame_returns_the_default_nonclient_result_only() {
    let style = frame_style();
    assert_eq!(
        ctl3d_dialog_frame_result(style, false, super::super::messages::WM_NCPAINT),
        Some(0)
    );
    assert_eq!(
        ctl3d_dialog_frame_result(style, false, WM_NCACTIVATE),
        Some(1)
    );
    // WS_CAPTION includes WS_DLGFRAME, so a captioned modal dialog still matches.
    let caption = style | 0x0080_0000;
    assert_eq!(
        ctl3d_dialog_frame_result(caption, false, WM_NCACTIVATE),
        Some(1)
    );
    assert_eq!(ctl3d_dialog_frame_result(style, true, WM_NCACTIVATE), None);
    assert_eq!(ctl3d_dialog_frame_result(style, false, WM_SETTEXT), None);
    assert_eq!(
        ctl3d_dialog_frame_result(style & !0x1000_0000, false, WM_NCACTIVATE),
        None
    );
    assert_eq!(
        ctl3d_dialog_frame_result(style & !0x0040_0000, false, WM_NCACTIVATE),
        None
    );
    assert_eq!(
        ctl3d_dialog_frame_result(style & !0x0000_0080, false, WM_NCACTIVATE),
        None
    );
}

struct FrameHost {
    facts: Option<Win16HostCtl3dFrameFacts>,
    queries: Vec<Win16HostWindow>,
    warnings: Vec<String>,
}

impl DosHost for FrameHost {
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

impl RuntimeHost for FrameHost {
    fn win16_ctl3d_frame(
        &mut self,
        window: Win16HostWindow,
    ) -> Result<Option<Win16HostCtl3dFrameFacts>, RuntimeError> {
        self.queries.push(window);
        Ok((window == TOKEN).then_some(self.facts).flatten())
    }
    fn report_diagnostic(&mut self, diagnostic: &Diagnostic) {
        self.warnings.push(diagnostic.to_string());
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

impl crate::RuntimeDdeHost for FrameHost {
    fn win16_dde_abort(&mut self) -> crate::Win16DdeAbortReceipt {
        panic!("unexpected host call")
    }
}
impl crate::RuntimeMciHost for FrameHost {}
impl crate::RuntimeMidiHost for FrameHost {}
impl crate::RuntimeNetbiosHost for FrameHost {}

fn frame_host(facts: Option<Win16HostCtl3dFrameFacts>) -> FrameHost {
    FrameHost {
        facts,
        queries: Vec::new(),
        warnings: Vec::new(),
    }
}

fn visible_frame() -> Win16HostCtl3dFrameFacts {
    Win16HostCtl3dFrameFacts {
        style: frame_style(),
        iconic: false,
    }
}

fn paint_request(module: Win16Ctl3dModule, window: u16, message: u16) -> Win16Ctl3dRequest {
    Win16Ctl3dRequest {
        module,
        ordinal: 20,
        name: Some("Ctl3dDlgFramePaint"),
        arguments: vec![
            Win16Ctl3dArgument::Word(window),
            Win16Ctl3dArgument::Word(message),
            Win16Ctl3dArgument::Word(1),
            Win16Ctl3dArgument::Dword(0x1111_2222),
        ],
    }
}

fn runtime_with_window() -> Runtime {
    let mut runtime = Runtime::load(&tiny_ne_executable(), &[], br"C:\CTL3D.NE").unwrap();
    let state = runtime.win16.as_mut().unwrap();
    state.window_handles.insert(WINDOW, TOKEN);
    runtime
}

#[test]
fn both_ctl3d_modules_return_the_activation_frame_result() {
    for module in [Win16Ctl3dModule::Ctl3d, Win16Ctl3dModule::Ctl3dV2] {
        let mut runtime = runtime_with_window();
        let mut host = frame_host(Some(visible_frame()));
        let value = runtime
            .win16
            .as_mut()
            .unwrap()
            .ctl3d_request(paint_request(module, WINDOW, WM_NCACTIVATE), &mut host)
            .unwrap();
        assert_eq!(value, 1);
        assert_eq!(host.queries, [TOKEN]);
        assert!(host.warnings.is_empty());
    }
}

#[test]
fn non_frame_messages_and_other_ordinals_stay_zero() {
    let mut runtime = runtime_with_window();
    let state = runtime.win16.as_mut().unwrap();
    let mut host = frame_host(Some(visible_frame()));
    assert_eq!(
        state
            .ctl3d_request(
                paint_request(Win16Ctl3dModule::Ctl3d, WINDOW, WM_SETTEXT),
                &mut host
            )
            .unwrap(),
        0
    );
    assert_eq!(
        state
            .ctl3d_request(
                paint_request(Win16Ctl3dModule::Ctl3d, 0x0200, WM_NCACTIVATE),
                &mut host
            )
            .unwrap(),
        0
    );
    assert_eq!(
        state
            .ctl3d_request(
                Win16Ctl3dRequest {
                    module: Win16Ctl3dModule::Ctl3d,
                    ordinal: 5,
                    name: Some("Ctl3dEnabled"),
                    arguments: Vec::new(),
                },
                &mut host
            )
            .unwrap(),
        0
    );
    assert_eq!(
        state
            .ctl3d_request(
                Win16Ctl3dRequest {
                    module: Win16Ctl3dModule::Ctl3dV2,
                    ordinal: 2,
                    name: Some("Ctl3dSubclassDlg"),
                    arguments: vec![
                        Win16Ctl3dArgument::Word(WINDOW),
                        Win16Ctl3dArgument::Word(0xffff)
                    ],
                },
                &mut host
            )
            .unwrap(),
        0
    );
    assert_eq!(host.queries, [TOKEN]);
    assert!(
        host.warnings
            .iter()
            .any(|warning| warning.contains("subclass"))
    );
    assert!(
        !host
            .warnings
            .iter()
            .any(|warning| warning.contains("dialog-frame style"))
    );
}

#[test]
fn missing_native_style_still_returns_long_zero() {
    let mut runtime = runtime_with_window();
    let mut host = frame_host(None);
    let value = runtime
        .win16
        .as_mut()
        .unwrap()
        .ctl3d_request(
            paint_request(Win16Ctl3dModule::Ctl3d, WINDOW, WM_NCACTIVATE),
            &mut host,
        )
        .unwrap();
    assert_eq!(value, 0);
    assert_eq!(host.queries, [TOKEN]);
    assert!(
        host.warnings
            .iter()
            .any(|warning| warning.contains("returning LONG zero"))
    );
}

fn frame_arguments(message: u16) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&0x1111_2222u32.to_le_bytes());
    bytes.extend_from_slice(&1u16.to_le_bytes());
    bytes.extend_from_slice(&message.to_le_bytes());
    bytes.extend_from_slice(&WINDOW.to_le_bytes());
    bytes
}

fn prepare(
    runtime: &mut Runtime,
    module: &[u8],
    ordinal: u16,
    arguments: &[u8],
) -> (u16, u16, u16) {
    let descriptor = lookup_export(module, ExportLookupTarget::Ordinal(ordinal)).unwrap();
    let win16_abi::Win16ExportStackCleanup::Fixed(cleanup) = descriptor.stack_cleanup else {
        panic!("CTL3D painter must use fixed Pascal cleanup");
    };
    assert_eq!(cleanup.callee_pop_bytes as usize, arguments.len());
    assert_eq!(cleanup.caller_pop_bytes, 0);
    let return_cs = runtime.cpu.regs.cs;
    let return_ip = 0x12_u16;
    let stack = runtime.cpu.regs.sp();
    let state = runtime.win16.as_mut().unwrap();
    let mut bytes = Vec::from(return_ip.to_le_bytes());
    bytes.extend_from_slice(&return_cs.to_le_bytes());
    bytes.extend_from_slice(arguments);
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
    runtime.cpu.regs.set_ax(0xa55a);
    runtime.cpu.regs.set_dx(0x5aa5);
    (return_cs, return_ip, stack + bytes.len() as u16)
}

#[test]
fn dispatch_projects_the_dialog_frame_long_and_leaves_other_calls_zero() {
    let mut runtime = runtime_with_window();
    let descriptor = lookup_export(b"CTL3D", ExportLookupTarget::Ordinal(20)).unwrap();
    assert_eq!(descriptor.return_kind, Win16ReturnKind::Dword);
    let return_to = prepare(&mut runtime, b"CTL3D", 20, &frame_arguments(WM_NCACTIVATE));
    let mut host = frame_host(Some(visible_frame()));
    runtime
        .win16
        .as_mut()
        .unwrap()
        .dispatch(
            &mut runtime.cpu,
            &mut runtime.memory,
            &mut runtime.dos,
            &mut host,
            0,
        )
        .unwrap();
    assert_eq!((runtime.cpu.regs.ax(), runtime.cpu.regs.dx()), (1, 0));
    assert_eq!(
        (
            runtime.cpu.regs.cs,
            runtime.cpu.regs.ip(),
            runtime.cpu.regs.sp()
        ),
        return_to
    );
    assert!(host.warnings.is_empty());

    let mut runtime = runtime_with_window();
    let return_to = prepare(
        &mut runtime,
        b"CTL3DV2",
        20,
        &frame_arguments(super::super::messages::WM_NCPAINT),
    );
    let mut host = frame_host(Some(visible_frame()));
    runtime
        .win16
        .as_mut()
        .unwrap()
        .dispatch(
            &mut runtime.cpu,
            &mut runtime.memory,
            &mut runtime.dos,
            &mut host,
            0,
        )
        .unwrap();
    assert_eq!((runtime.cpu.regs.ax(), runtime.cpu.regs.dx()), (0, 0));
    assert_eq!(
        (
            runtime.cpu.regs.cs,
            runtime.cpu.regs.ip(),
            runtime.cpu.regs.sp()
        ),
        return_to
    );

    let mut runtime = runtime_with_window();
    prepare(&mut runtime, b"CTL3D", 5, &[]);
    let mut host = frame_host(Some(visible_frame()));
    runtime
        .win16
        .as_mut()
        .unwrap()
        .dispatch(
            &mut runtime.cpu,
            &mut runtime.memory,
            &mut runtime.dos,
            &mut host,
            0,
        )
        .unwrap();
    assert_eq!((runtime.cpu.regs.ax(), runtime.cpu.regs.dx()), (0, 0x5aa5));
    assert!(host.queries.is_empty());
}

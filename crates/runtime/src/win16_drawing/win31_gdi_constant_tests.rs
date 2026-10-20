//! Windows 3.1 GDI constants that later Windows values must not replace.

use std::collections::VecDeque;

use super::super::super::test_support::tiny_ne_executable;
use crate::{
    Runtime, RuntimeError, RuntimeHost, Win16DrawingOperation, Win16DrawingRect,
    Win16DrawingResult, Win16GdiDeviceOperation, Win16GdiDeviceResult, Win16HostDc,
};
use devices::{keyboard::KeyStroke, video::ConsoleSnapshot};
use dos_kernel::{
    DosDirectoryEntry, DosFileAccess, DosFileSharing, DosHost, DosHostError, DosHostFile,
    DosHostSearch, DosSeekOrigin,
};
use guest_core::PhysAddr;
use win16_abi::{
    AccessRights, SegmentedPointer, Win16ApiRequest, window_geometry::Rect16,
};

const NATIVE_DC: Win16HostDc = Win16HostDc(0x1234_5678_9abc);
const TA_RTLREADING: u16 = 0x0100;
const TA_RIGHT: u16 = 0x0002;
const TA_BASELINE: u16 = 0x0018;
const DT_CENTER: u16 = 0x0001;
const DT_TABSTOP: u16 = 0x0080;
const DT_CALCRECT: u16 = 0x0400;
const DT_END_ELLIPSIS: u16 = 0x8000;
const SYSPAL_STATIC: u16 = 1;
const SYSPAL_NOSTATIC: u16 = 2;
const SYSPAL_NOSTATIC256: u16 = 3;

struct Host {
    drawing: Vec<Win16DrawingOperation>,
    device: Vec<Win16GdiDeviceOperation>,
    align: i32,
    draw: Win16DrawingResult,
    palette: VecDeque<i32>,
}

impl DosHost for Host {
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

impl RuntimeHost for Host {
    fn win16_gdi(
        &mut self,
        operation: Win16DrawingOperation,
    ) -> Result<Win16DrawingResult, RuntimeError> {
        self.drawing.push(operation);
        Ok(match self.drawing.last().unwrap() {
            Win16DrawingOperation::GetTextAlign { .. }
            | Win16DrawingOperation::SetTextAlign { .. } => Win16DrawingResult::Mode(self.align),
            Win16DrawingOperation::UserDrawText { .. } => self.draw.clone(),
            _ => panic!("unexpected drawing operation"),
        })
    }

    fn win16_gdi_device(
        &mut self,
        operation: Win16GdiDeviceOperation,
    ) -> Result<Win16GdiDeviceResult, RuntimeError> {
        self.device.push(operation);
        let value = self.palette.pop_front().expect("palette result");
        Ok(Win16GdiDeviceResult::Count(value))
    }

    fn epoch_seconds(&self) -> i64 { panic!("unexpected host call") }
    fn read_bios_key(&mut self) -> Result<KeyStroke, RuntimeError> { panic!("unexpected host call") }
    fn render_text(&mut self, _screen: &ConsoleSnapshot) -> Result<(), RuntimeError> { panic!("unexpected host call") }
}

impl crate::RuntimeDdeHost for Host {
    fn win16_dde_abort(&mut self) -> crate::Win16DdeAbortReceipt { panic!("unexpected host call") }
}
impl crate::RuntimeMciHost for Host {}
impl crate::RuntimeMidiHost for Host {}
impl crate::RuntimeNetbiosHost for Host {}

fn host(align: i32, palette: impl IntoIterator<Item = i32>) -> Host {
    Host {
        drawing: Vec::new(),
        device: Vec::new(),
        align,
        draw: Win16DrawingResult::DrawText {
            height: 8,
            rect: Some(Win16DrawingRect { left: 1, top: 2, right: 30, bottom: 12 }),
        },
        palette: palette.into_iter().collect(),
    }
}

fn dc(runtime: &mut Runtime) -> u16 {
    runtime
        .win16
        .as_mut()
        .unwrap()
        .guest_gdi
        .allocate_dc(NATIVE_DC)
        .unwrap()
}

fn loaded() -> Runtime {
    Runtime::load(&tiny_ne_executable(), &[], br"C:\GDI.NE").unwrap()
}

#[test]
fn text_align_drops_later_reading_bit_and_keeps_win31_flags() {
    let mut runtime = loaded();
    let dc = dc(&mut runtime);
    let state = runtime.win16.as_mut().unwrap();
    let mut host = host(i32::from(TA_BASELINE | TA_RTLREADING), []);
    let set = state
        .drawing_text_requests(
            Win16ApiRequest::GdiText(win16_abi::Win16GdiTextRequest::SetTextAlign {
                dc,
                alignment: TA_RIGHT | TA_RTLREADING,
            }),
            &mut runtime.memory,
            &mut host,
        )
        .unwrap();
    assert_eq!(set, u32::from(TA_BASELINE));
    assert_eq!(
        host.drawing,
        [Win16DrawingOperation::SetTextAlign {
            dc: NATIVE_DC,
            alignment: u32::from(TA_RIGHT),
        }]
    );

    host.align = -1;
    host.drawing.clear();
    let failed = state
        .drawing_text_requests(
            Win16ApiRequest::GdiText(win16_abi::Win16GdiTextRequest::SetTextAlign {
                dc,
                alignment: TA_BASELINE | TA_RTLREADING,
            }),
            &mut runtime.memory,
            &mut host,
        )
        .unwrap();
    assert_eq!(failed, 0);
    assert_eq!(
        host.drawing,
        [Win16DrawingOperation::SetTextAlign {
            dc: NATIVE_DC,
            alignment: u32::from(TA_BASELINE),
        }]
    );

    host.align = i32::from(TA_RIGHT | TA_RTLREADING);
    host.drawing.clear();
    let get = state
        .drawing_text_requests(
            Win16ApiRequest::GdiText(win16_abi::Win16GdiTextRequest::GetTextAlign { dc }),
            &mut runtime.memory,
            &mut host,
        )
        .unwrap();
    assert_eq!(get, u32::from(TA_RIGHT));

    host.drawing.clear();
    let missing = state
        .drawing_text_requests(
            Win16ApiRequest::GdiText(win16_abi::Win16GdiTextRequest::SetTextAlign {
                dc: 0,
                alignment: TA_RIGHT,
            }),
            &mut runtime.memory,
            &mut host,
        )
        .unwrap();
    assert_eq!(missing, 0);
    assert!(host.drawing.is_empty());
}

#[test]
fn draw_text_drops_ellipsis_and_keeps_tab_count() {
    let mut runtime = loaded();
    let dc = dc(&mut runtime);
    let selector = runtime
        .win16
        .as_mut()
        .unwrap()
        .selectors
        .alloc_block(
            PhysAddr(0x70000),
            0x100,
            AccessRights::read_write(),
            &runtime.memory,
        )
        .unwrap();
    let output = SegmentedPointer::new(selector, 0x20).far_value();
    let rect = Rect16 { left: 0, top: 0, right: 40, bottom: 16 };
    let state = runtime.win16.as_mut().unwrap();
    let mut host = host(0, []);

    let height = state
        .user_service_drawing(
            draw_text(dc, DT_CENTER | DT_END_ELLIPSIS, 0, rect),
            &mut runtime.memory,
            &mut host,
        )
        .unwrap();
    assert_eq!(height, 8);
    assert_eq!(draw_flags(&host), u32::from(DT_CENTER));

    host.drawing.clear();
    let tab_count = 128_u16;
    let flags = DT_TABSTOP | (tab_count << 8);
    let height = state
        .user_service_drawing(
            draw_text(dc, flags, 0, rect),
            &mut runtime.memory,
            &mut host,
        )
        .unwrap();
    assert_eq!(height, 8);
    assert_eq!(draw_flags(&host), u32::from(flags));

    host.drawing.clear();
    let height = state
        .user_service_drawing(
            draw_text(dc, DT_CALCRECT | DT_END_ELLIPSIS, output, rect),
            &mut runtime.memory,
            &mut host,
        )
        .unwrap();
    assert_eq!(height, 8);
    assert_eq!(draw_flags(&host), u32::from(DT_CALCRECT));
    assert_eq!(read_rect(&runtime, output), [1, 2, 30, 12]);
}

#[test]
fn palette_use_rejects_later_mode_and_restores_it() {
    let mut runtime = loaded();
    let dc = dc(&mut runtime);
    let state = runtime.win16.as_mut().unwrap();
    let mut host = host(0, []);

    let rejected = state
        .system_palette_use(dc, Some(SYSPAL_NOSTATIC256), &mut host)
        .unwrap();
    assert_eq!(rejected, 0);
    assert!(host.device.is_empty());

    host.palette.push_back(i32::from(SYSPAL_NOSTATIC));
    let previous = state
        .system_palette_use(dc, Some(SYSPAL_STATIC), &mut host)
        .unwrap();
    assert_eq!(previous, u32::from(SYSPAL_NOSTATIC));
    assert_eq!(
        host.device,
        [Win16GdiDeviceOperation::SetSystemPaletteUse {
            dc: NATIVE_DC,
            use_mode: SYSPAL_STATIC,
        }]
    );

    host.device.clear();
    host.palette.push_back(i32::from(SYSPAL_NOSTATIC256));
    host.palette.push_back(i32::from(SYSPAL_NOSTATIC256));
    let restored = state
        .system_palette_use(dc, Some(SYSPAL_STATIC), &mut host)
        .unwrap();
    assert_eq!(restored, 0);
    assert_eq!(
        host.device,
        [
            Win16GdiDeviceOperation::SetSystemPaletteUse {
                dc: NATIVE_DC,
                use_mode: SYSPAL_STATIC,
            },
            Win16GdiDeviceOperation::SetSystemPaletteUse {
                dc: NATIVE_DC,
                use_mode: SYSPAL_NOSTATIC256,
            },
        ]
    );

    host.device.clear();
    host.palette.push_back(i32::from(SYSPAL_NOSTATIC256));
    let current = state.system_palette_use(dc, None, &mut host).unwrap();
    assert_eq!(current, 0);
    assert_eq!(
        host.device,
        [Win16GdiDeviceOperation::GetSystemPaletteUse { dc: NATIVE_DC }]
    );

    host.device.clear();
    host.palette.push_back(i32::from(SYSPAL_STATIC));
    let current = state.system_palette_use(dc, None, &mut host).unwrap();
    assert_eq!(current, u32::from(SYSPAL_STATIC));

    host.device.clear();
    let missing = state.system_palette_use(0, Some(SYSPAL_STATIC), &mut host).unwrap();
    assert_eq!(missing, 0);
    assert!(host.device.is_empty());
}

fn draw_text(dc: u16, flags: u16, rect_output: u32, rect: Rect16) -> Win16ApiRequest {
    Win16ApiRequest::User(win16_abi::Win16UserRequest::Drawing(
        win16_abi::Win16UserDrawingRequest::DrawText {
            dc,
            text: b"Hi".to_vec(),
            count: 2,
            rect: Some(rect),
            rect_output,
            flags,
        },
    ))
}

fn draw_flags(host: &Host) -> u32 {
    match host.drawing.last() {
        Some(Win16DrawingOperation::UserDrawText { flags, .. }) => *flags,
        _ => panic!("DrawText was not called"),
    }
}

fn read_rect(runtime: &Runtime, far: u32) -> [i16; 4] {
    let state = runtime.win16.as_ref().unwrap();
    let pointer = state.selectors.pointer_from_far(far).unwrap();
    let mut bytes = [0; 8];
    state.selectors.read(&runtime.memory, pointer, &mut bytes).unwrap();
    std::array::from_fn(|index| i16::from_le_bytes([bytes[2 * index], bytes[2 * index + 1]]))
}

#[test]
fn text_align_host_error_is_not_reported_as_an_alignment() {
    // GDI_ERROR is negative. Masking it would look like every Win16 flag.
    assert_eq!(super::win31_text_align(-1), 0);
    assert_eq!(super::win31_text_align(i32::from(TA_RIGHT | TA_RTLREADING)), u32::from(TA_RIGHT));
}
